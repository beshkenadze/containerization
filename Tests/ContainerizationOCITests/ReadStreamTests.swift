//===----------------------------------------------------------------------===//
// Copyright © 2026 Apple Inc. and the Containerization project authors.
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

import ContainerizationExtras
import ContainerizationIO
import Foundation
import NIOCore
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Musl)
import Musl
#elseif canImport(Glibc)
import Glibc
#endif

@Suite
struct ReadStreamTests {
    enum View: CaseIterable {
        case byteBuffer
        case data
    }

    private static let chunkSize = 8

    @Test(arguments: View.allCases)
    func readsOnDemand(_ view: View) async throws {
        let dir = FileManager.default.uniqueTemporaryDirectory(create: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("blob")
        try Data("AAAABBBBCCCC".utf8).write(to: file)

        let next = Self.chunks(of: try ReadStream(url: file, bufferSize: 4), view)
        #expect(await next() == Data("AAAA".utf8))

        let handle = try FileHandle(forWritingTo: file)
        try handle.seek(toOffset: 4)
        try handle.write(contentsOf: Data("XXXXYYYY".utf8))
        try handle.close()

        let rest = await Self.drain(next)
        #expect(Self.text(rest) == ["XXXX", "YYYY"])
    }

    @Test(arguments: [0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3 * chunkSize + 5])
    func roundTrips(size: Int) async throws {
        let dir = FileManager.default.uniqueTemporaryDirectory(create: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("blob")
        let payload = Data((0..<size).map { UInt8(truncatingIfNeeded: $0) })
        try payload.write(to: file)

        var sizes = Array(repeating: Self.chunkSize, count: size / Self.chunkSize)
        if size % Self.chunkSize != 0 {
            sizes.append(size % Self.chunkSize)
        }

        for view in View.allCases {
            let sources = [
                try ReadStream(url: file, bufferSize: Self.chunkSize),
                ReadStream(data: payload, bufferSize: Self.chunkSize),
            ]
            for source in sources {
                let chunks = await Self.drain(Self.chunks(of: source, view))
                #expect(chunks.map(\.count) == sizes)
                #expect(Data(chunks.joined()) == payload)
            }
        }
    }

    @Test(arguments: View.allCases)
    func defaultInitIsEmpty(_ view: View) async {
        #expect(await Self.drain(Self.chunks(of: ReadStream(), view)).isEmpty)
    }

    @Test(arguments: View.allCases)
    func resetEndsEarlierStreamAndRereadsFromStart(_ view: View) async throws {
        let dir = FileManager.default.uniqueTemporaryDirectory(create: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("blob")
        let payload = Data("AAAABBBBCCCC".utf8)
        try payload.write(to: file)

        for source in [try ReadStream(url: file, bufferSize: 4), ReadStream(data: payload, bufferSize: 4)] {
            let first = Self.chunks(of: source, view)
            #expect(await first() == Data("AAAA".utf8))

            try source.reset()
            #expect(await Self.drain(first).isEmpty)
            #expect(Data(await Self.drain(Self.chunks(of: source, view)).joined()) == payload)

            try source.reset()
            #expect(Data(await Self.drain(Self.chunks(of: source, view)).joined()) == payload)
        }

        let source = try ReadStream(url: file, bufferSize: 4)
        let first = Self.chunks(of: source, view)
        #expect(await first() == Data("AAAA".utf8))
        #expect(await Self.drain(Self.chunks(of: source, view)).isEmpty)
        try source.reset()
        let openAfterReset = try withExtendedLifetime(first) { try Self.openDescriptors(for: file) }
        #expect(openAfterReset == 0)
        #expect(await Self.drain(first).isEmpty)
    }

    @Test(arguments: View.allCases)
    func closesFileWhenDrainedAbandonedOrCancelled(_ view: View) async throws {
        let dir = FileManager.default.uniqueTemporaryDirectory(create: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("blob")
        try Data("AAAABBBBCCCC".utf8).write(to: file)

        do {
            let next = Self.chunks(of: try ReadStream(url: file, bufferSize: 4), view)
            #expect(await next() == Data("AAAA".utf8))
            let openWhileReading = try withExtendedLifetime(next) { try Self.openDescriptors(for: file) }
            #expect(openWhileReading == 1)

            #expect(await Self.drain(next).count == 2)
            let openAfterEnd = try withExtendedLifetime(next) { try Self.openDescriptors(for: file) }
            #expect(openAfterEnd == 0)
        }

        let source = try ReadStream(url: file, bufferSize: 4)
        do {
            let next = Self.chunks(of: source, view)
            #expect(await next() == Data("AAAA".utf8))
        }
        let openAfterAbandon = try withExtendedLifetime(source) { try Self.openDescriptors(for: file) }
        #expect(openAfterAbandon == 0)

        let afterCancel = try await Task {
            let next = Self.chunks(of: try ReadStream(url: file, bufferSize: 4), view)
            _ = await next()
            withUnsafeCurrentTask { $0?.cancel() }
            return await Self.drain(next)
        }.value
        #expect(Self.text(afterCancel) == [])
        #expect(try Self.openDescriptors(for: file) == 0)
    }

    private static func chunks(of stream: ReadStream, _ view: View) -> () async -> Data? {
        switch view {
        case .byteBuffer:
            var iterator = stream.stream.makeAsyncIterator()
            return { await iterator.next().map { Data($0.readableBytesView) } }
        case .data:
            var iterator = stream.dataStream.makeAsyncIterator()
            return { await iterator.next() }
        }
    }

    private static func drain(_ next: () async -> Data?) async -> [Data] {
        var chunks: [Data] = []
        while let chunk = await next() {
            chunks.append(chunk)
        }
        return chunks
    }

    private static func text(_ chunks: [Data]) -> [String] {
        chunks.map { String(decoding: $0, as: UTF8.self) }
    }

    private static func openDescriptors(for url: URL) throws -> Int {
        var file = stat()
        let rc = stat(url.path, &file)
        try #require(rc == 0)
        return try FileManager.default.contentsOfDirectory(atPath: "/dev/fd").compactMap { Int32($0) }.filter { fd in
            var open = stat()
            return fstat(fd, &open) == 0 && open.st_dev == file.st_dev && open.st_ino == file.st_ino
        }.count
    }
}
