//===----------------------------------------------------------------------===//
// Copyright © 2025-2026 Apple Inc. and the Containerization project authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//===----------------------------------------------------------------------===//

import ContainerizationOS
import Foundation
import NIO
import Synchronization

/// `ReadStream` is a utility type for streaming data from a `URL`
/// or `Data` blob.
public class ReadStream {
    public static let bufferSize = Int(1.mib())

    private var reader: Reader?
    private weak var issued: Reader?
    private let buffSize: Int
    private let data: Data?
    private let url: URL?

    public init() {
        reader = Reader(InputStream(data: .init()), bufferSize: Self.bufferSize)
        buffSize = Self.bufferSize
        self.data = Data()
        self.url = nil
    }

    public init(url: URL, bufferSize: Int = bufferSize) throws {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw Error.noSuchFileOrDirectory(url)
        }
        guard let stream = InputStream(url: url) else {
            throw Error.failedToCreateStream
        }
        self.reader = Reader(stream, bufferSize: bufferSize)
        self.buffSize = bufferSize
        self.url = url
        self.data = nil
    }

    public init(data: Data, bufferSize: Int = bufferSize) {
        self.reader = Reader(InputStream(data: data), bufferSize: bufferSize)
        self.buffSize = bufferSize
        self.url = nil
        self.data = data
    }

    /// Resets the read stream. This either reassigns
    /// the data buffer or url to a new InputStream internally.
    public func reset() throws {
        issued?.close()
        if let url = self.url {
            guard let s = InputStream(url: url) else {
                throw Error.failedToCreateStream
            }
            self.reader = Reader(s, bufferSize: buffSize)
            return
        }
        let data = self.data ?? Data()
        self.reader = Reader(InputStream(data: data), bufferSize: buffSize)
    }

    /// Get access to an `AsyncStream` of `ByteBuffer`'s from the input source.
    public var stream: AsyncStream<ByteBuffer> {
        let reader = takeReader()
        return AsyncStream(unfolding: { reader?.next().map { ByteBuffer(bytes: $0) } })
    }

    /// Get access to an `AsyncStream` of `Data` objects from the input source.
    public var dataStream: AsyncStream<Data> {
        let reader = takeReader()
        return AsyncStream(unfolding: { reader?.next().map { Data($0) } })
    }

    private func takeReader() -> Reader? {
        guard let reader = self.reader.take() else {
            return nil
        }
        issued = reader
        return reader
    }
}

private final class Reader: Sendable {
    private let input: Mutex<InputStream?>
    private let bufferSize: Int

    init(_ input: sending InputStream, bufferSize: Int) {
        self.input = Mutex(input)
        self.bufferSize = bufferSize
    }

    deinit {
        close()
    }

    func close() {
        input.withLock { input in
            input?.close()
            input = nil
        }
    }

    func next() -> ArraySlice<UInt8>? {
        input.withLock { input in
            guard let stream = input else {
                return nil
            }
            if stream.streamStatus == .notOpen {
                stream.open()
            }
            var chunk = [UInt8](repeating: 0, count: bufferSize)
            let count = stream.read(&chunk, maxLength: bufferSize)
            guard count > 0 else {
                stream.close()
                input = nil
                return nil
            }
            return chunk[..<count]
        }
    }
}

extension ReadStream {
    /// Errors that can be encountered while using a `ReadStream`.
    public enum Error: Swift.Error, CustomStringConvertible {
        case failedToCreateStream
        case noSuchFileOrDirectory(_ p: URL)

        public var description: String {
            switch self {
            case .failedToCreateStream:
                return "failed to create stream"
            case .noSuchFileOrDirectory(let p):
                return "no such file or directory: \(p.path)"
            }
        }
    }
}
