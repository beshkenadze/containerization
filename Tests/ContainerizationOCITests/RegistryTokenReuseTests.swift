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
import Synchronization
import Testing

@testable import ContainerizationOCI

@Suite("RegistryClient bearer token reuse", .timeLimit(.minutes(1)))
struct RegistryTokenReuseTests {
    private static let group = MultiThreadedEventLoopGroup.singleton
    private static let repoName = "test/image"

    private final class TokenRegistry: Sendable {
        enum AnonymousPolicy {
            case challenge
            case accept
            case forbid
        }

        private struct State {
            var issued: Set<String> = []
            var revoked: Set<String> = []
            var requests: [MockRegistryRequest] = []
            var anonymous: AnonymousPolicy = .challenge
            var unavailableResponses = 0
        }

        private let state = Mutex(State())
        private let tokenFields: String
        private let challengesRevokedTokens: Bool

        init(tokenFields: String = #""expires_in":300"#, challengesRevokedTokens: Bool = true) {
            self.tokenFields = tokenFields
            self.challengesRevokedTokens = challengesRevokedTokens
        }

        var tokenRequests: Int { state.withLock { $0.issued.count } }
        var requests: [MockRegistryRequest] { state.withLock { $0.requests } }
        var authorizations: [String?] { requests.map { $0.headers.first(name: "Authorization") } }

        func revokeIssuedTokens() {
            state.withLock { $0.revoked.formUnion($0.issued) }
        }

        func setAnonymousPolicy(_ policy: AnonymousPolicy) {
            state.withLock { $0.anonymous = policy }
        }

        func failNextRequests(_ count: Int) {
            state.withLock { $0.unavailableResponses = count }
        }

        func respond(to request: MockRegistryRequest) -> MockRegistryResponse {
            if request.uri.hasPrefix("/token") {
                let token = state.withLock { state in
                    let token = "token-\(state.issued.count + 1)"
                    state.issued.insert("Bearer \(token)")
                    return token
                }
                return .status(.ok, body: Data(#"{"token":"\#(token)",\#(tokenFields)}"#.utf8))
            }

            let authorization = request.headers.first(name: "Authorization")
            let (accepted, revoked, anonymous, unavailable) = state.withLock { state in
                state.requests.append(request)
                if state.unavailableResponses > 0 {
                    state.unavailableResponses -= 1
                    return (false, false, state.anonymous, true)
                }
                guard let authorization else {
                    return (false, false, state.anonymous, false)
                }
                return (state.issued.contains(authorization) && !state.revoked.contains(authorization), state.revoked.contains(authorization), state.anonymous, false)
            }
            if unavailable {
                return .status(.serviceUnavailable)
            }
            if accepted || (authorization == nil && anonymous == .accept) {
                return Self.route(request)
            }
            if authorization == nil, anonymous == .forbid {
                return .status(.forbidden)
            }
            if revoked, !challengesRevokedTokens {
                return .status(.forbidden)
            }
            let host = request.headers.first(name: "Host") ?? ""
            var headers = HTTPHeaders()
            headers.add(name: "WWW-Authenticate", value: #"Bearer realm="https://\#(host)/token",service="mock",scope="repository:\#(repoName):pull,push""#)
            return .status(.unauthorized, headers: headers)
        }

        private static func route(_ request: MockRegistryRequest) -> MockRegistryResponse {
            var headers = HTTPHeaders()
            switch request.method {
            case .HEAD:
                return .status(.notFound)
            case .POST:
                headers.add(name: "Location", value: "/v2/\(repoName)/blobs/uploads/\(UUID().uuidString)")
                return .status(.accepted, headers: headers)
            case .PUT:
                let digest = URLComponents(string: request.uri)?.queryItems?.first { $0.name == "digest" }?.value ?? ""
                headers.add(name: "Docker-Content-Digest", value: digest)
                return .status(.created, headers: headers)
            default:
                return .status(.ok)
            }
        }
    }

    private static func start(_ registry: TokenRegistry, retryOptions: RetryOptions? = nil) async throws -> (MockRegistryServer, RegistryClient) {
        let server = try await MockRegistryServer(eventLoopGroup: group, tls: true) { registry.respond(to: $0) }
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.certificateVerification = .none
        let client = RegistryClient(host: "127.0.0.1", scheme: "https", port: server.port, retryOptions: retryOptions, tlsConfiguration: tls)
        return (server, client)
    }

    private static func pushBlob(_ client: RegistryClient, _ data: Data) async throws {
        let descriptor = Descriptor(mediaType: MediaTypes.imageLayerGzip, digest: SHA256.hash(data: data).digestString, size: Int64(data.count))
        try await client.push(
            name: repoName,
            ref: "latest",
            descriptor: descriptor,
            streamGenerator: {
                AsyncStream<ByteBuffer> { continuation in
                    continuation.yield(ByteBuffer(bytes: data))
                    continuation.finish()
                }
            },
            progress: nil
        )
    }

    @Test("a blob push sends the token from the first challenge with every later request")
    func pushReusesToken() async throws {
        let registry = TokenRegistry()
        let (server, client) = try await Self.start(registry)
        defer { Task { try? await server.shutdown() } }

        try await Self.pushBlob(client, Data("layer".utf8))

        #expect(registry.requests.map(\.method) == [.HEAD, .HEAD, .POST, .PUT])
        #expect(registry.authorizations == [nil, "Bearer token-1", "Bearer token-1", "Bearer token-1"])
        #expect(registry.tokenRequests == 1)
    }

    @Test("concurrent blob pushes on one client send every blob once with a token")
    func concurrentPushesReuseToken() async throws {
        let registry = TokenRegistry()
        let (server, client) = try await Self.start(registry)
        defer { Task { try? await server.shutdown() } }

        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<8 {
                group.addTask { try await Self.pushBlob(client, Data("layer-\(index)".utf8)) }
            }
            try await group.waitForAll()
        }

        let puts = registry.requests.filter { $0.method == .PUT }
        #expect(puts.count == 8)
        #expect(puts.allSatisfy { $0.headers.first(name: "Authorization") != nil })
        #expect(registry.tokenRequests <= 8)
    }

    @Test("a rejected cached token is replaced by a fresh token")
    func rejectedCachedTokenIsReplaced() async throws {
        let registry = TokenRegistry()
        let (server, client) = try await Self.start(registry)
        defer { Task { try? await server.shutdown() } }

        try await client.ping()
        registry.revokeIssuedTokens()
        try await client.ping()
        try await client.ping()

        #expect(registry.authorizations == [nil, "Bearer token-1", "Bearer token-1", "Bearer token-2", "Bearer token-2"])
        #expect(registry.tokenRequests == 2)
    }

    @Test("a cached token rejected without a challenge is dropped for an unauthenticated retry")
    func cachedTokenRejectedWithoutChallengeIsDropped() async throws {
        let registry = TokenRegistry(challengesRevokedTokens: false)
        let (server, client) = try await Self.start(registry)
        defer { Task { try? await server.shutdown() } }

        try await client.ping()
        registry.revokeIssuedTokens()
        try await client.ping()

        #expect(registry.authorizations == [nil, "Bearer token-1", "Bearer token-1", nil, "Bearer token-2"])
        #expect(registry.tokenRequests == 2)
    }

    @Test("a cached token rejected without a challenge is not sent with later requests")
    func cachedTokenRejectedWithoutChallengeIsForgotten() async throws {
        let registry = TokenRegistry(challengesRevokedTokens: false)
        let (server, client) = try await Self.start(registry)
        defer { Task { try? await server.shutdown() } }

        try await client.ping()
        registry.revokeIssuedTokens()
        registry.setAnonymousPolicy(.accept)
        try await client.ping()
        try await client.ping()

        #expect(registry.authorizations == [nil, "Bearer token-1", "Bearer token-1", nil, nil])
        #expect(registry.tokenRequests == 1)
    }

    @Test("an unauthenticated retry after a rejected cached token is sent one time")
    func unauthenticatedRetryIsSentOneTime() async throws {
        let registry = TokenRegistry(challengesRevokedTokens: false)
        let (server, client) = try await Self.start(registry)
        defer { Task { try? await server.shutdown() } }

        try await client.ping()
        registry.revokeIssuedTokens()
        registry.setAnonymousPolicy(.forbid)
        await #expect {
            try await client.ping()
        } throws: { error in
            guard case RegistryClient.Error.invalidStatus(_, let status, _) = error else {
                return false
            }
            return status == .forbidden
        }

        #expect(registry.authorizations == [nil, "Bearer token-1", "Bearer token-1", nil])
        #expect(registry.tokenRequests == 1)
    }

    @Test("a cached token that expires during a retry delay is not sent with the retry")
    func cachedTokenExpiredBeforeRetryIsDropped() async throws {
        let registry = TokenRegistry(tokenFields: #""expires_in":2"#)
        let retryOptions = RetryOptions(maxRetries: 1, retryInterval: 2_500_000_000) { $0.status == .serviceUnavailable }
        let (server, client) = try await Self.start(registry, retryOptions: retryOptions)
        defer { Task { try? await server.shutdown() } }

        try await client.ping()
        registry.setAnonymousPolicy(.accept)
        registry.failNextRequests(1)
        try await client.ping()

        #expect(registry.authorizations == [nil, "Bearer token-1", "Bearer token-1", nil])
        #expect(registry.tokenRequests == 1)
    }

    @Test("an expired token is not sent again")
    func expiredTokenIsNotReused() async throws {
        let registry = TokenRegistry(tokenFields: #""expires_in":60,"issued_at":"2020-01-01T00:00:00.000Z""#)
        let (server, client) = try await Self.start(registry)
        defer { Task { try? await server.shutdown() } }

        try await client.ping()
        try await client.ping()

        #expect(registry.authorizations == [nil, "Bearer token-1", nil, "Bearer token-2"])
        #expect(registry.tokenRequests == 2)
    }
}
