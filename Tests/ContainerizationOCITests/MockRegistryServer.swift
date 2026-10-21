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

import Crypto
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import X509

// MARK: - MockRegistryRequest / MockRegistryResponse

/// An inbound HTTP request captured by the mock registry server.
struct MockRegistryRequest: Sendable {
    let method: HTTPMethod
    let uri: String
    let headers: HTTPHeaders
}

/// A canned HTTP response produced by the mock registry server.
struct MockRegistryResponse: Sendable {
    let status: HTTPResponseStatus
    let body: Data
    let headers: HTTPHeaders

    static func status(_ status: HTTPResponseStatus, headers: HTTPHeaders = [:], body: Data = .init()) -> MockRegistryResponse {
        MockRegistryResponse(status: status, body: body, headers: headers)
    }
}

// MARK: - MockRegistryServer

/// An in-process HTTP/1.1 server bound to `127.0.0.1` on an OS-assigned port,
/// used to stand in for a registry (honest or malicious) in `RegistryClient` tests.
///
/// Modeled on `Tests/CloudHypervisorTests/StubHTTPServer.swift`, which binds to a
/// Unix domain socket instead — `RegistryClient` talks real HTTP over TCP, so this
/// variant binds a TCP listener rather than reusing that one directly.
final class MockRegistryServer: Sendable {
    /// The port this server is listening on.
    let port: Int

    private let channel: Channel

    init(
        eventLoopGroup: any EventLoopGroup,
        tls: Bool = false,
        handler: @escaping @Sendable (MockRegistryRequest) -> MockRegistryResponse
    ) async throws {
        let sslContext = tls ? try NIOSSLContext(configuration: Self.makeServerTLSConfiguration()) : nil
        let bootstrap = ServerBootstrap(group: eventLoopGroup)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    if let sslContext {
                        try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: sslContext))
                    }
                    try channel.pipeline.syncOperations.configureHTTPServerPipeline(
                        withPipeliningAssistance: false
                    )
                    try channel.pipeline.syncOperations.addHandler(
                        MockRegistryRequestHandler(userHandler: handler)
                    )
                }
            }

        let boundChannel =
            try await bootstrap
            .bind(host: "127.0.0.1", port: 0)
            .get()

        guard let port = boundChannel.localAddress?.port else {
            try await boundChannel.close().get()
            fatalError("bound channel has no local port")
        }

        self.port = port
        self.channel = boundChannel
    }

    /// Stop accepting connections and close the listening socket.
    func shutdown() async throws {
        try await channel.close().get()
    }

    static func makeServerTLSConfiguration() throws -> TLSConfiguration {
        let certificateKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let subject = try DistinguishedName { CommonName("localhost") }
        let now = Date()

        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: certificateKey.publicKey,
            notValidBefore: now.addingTimeInterval(-60),
            notValidAfter: now.addingTimeInterval(60 * 60),
            issuer: subject,
            subject: subject,
            extensions: Certificate.Extensions(),
            issuerPrivateKey: certificateKey
        )

        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(try NIOSSLCertificate(bytes: certificate.serializeAsPEM().derBytes, format: .der))],
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: certificateKey.serializeAsPEM().derBytes, format: .der))
        )
        configuration.applicationProtocols = ["http/1.1"]
        return configuration
    }
}

// MARK: - MockRegistryRequestHandler

/// Handles a single inbound HTTP/1.1 request and writes back the user handler's response.
private final class MockRegistryRequestHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let userHandler: @Sendable (MockRegistryRequest) -> MockRegistryResponse

    // Mutable inbound state — only touched on the event loop.
    private var pendingMethod: HTTPMethod?
    private var pendingURI: String?
    private var pendingHeaders: HTTPHeaders = [:]

    init(userHandler: @escaping @Sendable (MockRegistryRequest) -> MockRegistryResponse) {
        self.userHandler = userHandler
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            pendingMethod = head.method
            pendingURI = head.uri
            pendingHeaders = head.headers
        case .body:
            break
        case .end:
            guard let method = pendingMethod, let uri = pendingURI else {
                context.close(promise: nil)
                return
            }
            let request = MockRegistryRequest(method: method, uri: uri, headers: pendingHeaders)
            let response = userHandler(request)
            writeResponse(context: context, method: method, response: response)
        }
    }

    private func writeResponse(context: ChannelHandlerContext, method: HTTPMethod, response: MockRegistryResponse) {
        var respHeaders = response.headers
        respHeaders.replaceOrAdd(name: "Content-Length", value: "\(response.body.count)")
        respHeaders.replaceOrAdd(name: "Connection", value: "close")

        let head = HTTPResponseHead(version: .http1_1, status: response.status, headers: respHeaders)
        context.write(wrapOutboundOut(.head(head)), promise: nil)

        // HEAD responses never carry a body, matching a real registry's HEAD /manifests/<ref>.
        if method != .HEAD, !response.body.isEmpty {
            var buf = context.channel.allocator.buffer(capacity: response.body.count)
            buf.writeBytes(response.body)
            context.write(wrapOutboundOut(.body(.byteBuffer(buf))), promise: nil)
        }

        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            boundContext.value.close(promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        context.close(promise: nil)
    }
}
