package com.cipherbird.cb2.example.service;

import com.cipherbird.cb2.Cb2Exception;
import com.cipherbird.cb2.Json;
import com.cipherbird.cb2.LocalKey;
import com.cipherbird.cb2.PublicKey;
import com.cipherbird.cb2.Rules;
import com.cipherbird.cb2.SecretKey;
import com.cipherbird.cb2.Token;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The service. POST /token takes a client's kcb2.public key and returns a
 * cb2.local access token bound to it (cnf) and a cb2.public id token.
 * GET /public-key publishes the key that verifies id tokens. GET /me
 * opens the access token from the Authorization header and checks the
 * holder proof from the CB2-Proof header against the request it came
 * with, refusing a proof id it has seen before.
 */
final class Server implements AutoCloseable {
    private static final DateTimeFormatter RFC3339 = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssxxx");

    private final HttpServer http;
    private final ExecutorService pool = Executors.newFixedThreadPool(4);
    private final LocalKey accessKey = LocalKey.generate();
    private final SecretKey signer = SecretKey.generate();
    private final Set<String> proofsSeen = ConcurrentHashMap.newKeySet();
    private final String origin;

    Server(InetSocketAddress address) throws IOException {
        http = HttpServer.create(address, 0);
        http.createContext("/token", this::token);
        http.createContext("/public-key", this::publicKey);
        http.createContext("/me", this::me);
        http.setExecutor(pool);
        http.start();
        origin = "http://127.0.0.1:" + http.getAddress().getPort();
    }

    String origin() {
        return origin;
    }

    private void token(HttpExchange exchange) throws IOException {
        String clientKey = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).trim();
        try (PublicKey parsed = PublicKey.fromPaserk(clientKey)) {
            Instant now = Instant.now();
            String access = Token.seal(accessKey, "{\"iss\":" + Json.quote(origin) + ",\"aud\":\"api\",\"sub\":\"user-1\","
                    + "\"scope\":\"read\",\"iat\":" + time(now) + ",\"exp\":" + time(now.plusSeconds(600))
                    + ",\"jti\":" + Json.quote(UUID.randomUUID().toString())
                    + ",\"cnf\":" + Json.quote(parsed.toPaserk()) + "}");
            String id = Token.sign(signer, "{\"iss\":" + Json.quote(origin) + ",\"aud\":\"client\",\"sub\":\"user-1\","
                    + "\"name\":\"Ada\",\"iat\":" + time(now) + ",\"exp\":" + time(now.plusSeconds(600)) + "}");
            send(exchange, 200, "{\"access_token\":" + Json.quote(access) + ",\"id_token\":" + Json.quote(id) + "}");
        } catch (Cb2Exception e) {
            send(exchange, 400, "{\"error\":" + Json.quote(e.name()) + "}");
        }
    }

    private void publicKey(HttpExchange exchange) throws IOException {
        try (PublicKey verifier = signer.publicKey()) {
            send(exchange, 200, verifier.toPaserk());
        }
    }

    private void me(HttpExchange exchange) throws IOException {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        String proof = exchange.getRequestHeaders().getFirst("CB2-Proof");
        if (authorization == null || !authorization.startsWith("CB2 ")) {
            send(exchange, 401, "{\"error\":\"no token\"}");
            return;
        }
        Rules rules = new Rules()
                .issuer(origin)
                .audience("api")
                .request(exchange.getRequestMethod(), origin + exchange.getRequestURI())
                .proofReplay(proofsSeen::add);
        if (proof != null) {
            rules.proof(proof);
        }
        try {
            send(exchange, 200, Token.open(accessKey, authorization.substring(4), rules));
        } catch (Cb2Exception e) {
            send(exchange, 401, "{\"error\":" + Json.quote(e.name()) + "}");
        }
    }

    private static String time(Instant instant) {
        return Json.quote(RFC3339.format(instant.atOffset(ZoneOffset.UTC)));
    }

    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    @Override
    public void close() {
        http.stop(0);
        pool.shutdown();
        accessKey.close();
        signer.close();
    }
}
