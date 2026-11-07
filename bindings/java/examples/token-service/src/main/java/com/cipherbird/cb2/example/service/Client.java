package com.cipherbird.cb2.example.service;

import com.cipherbird.cb2.Holder;
import com.cipherbird.cb2.PublicKey;
import com.cipherbird.cb2.Rules;
import com.cipherbird.cb2.SecretKey;
import com.cipherbird.cb2.Token;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The client: gets tokens bound to its own signing pair, verifies the id
 * token with the key the service publishes, then calls GET /me with a
 * fresh holder proof, and tries the requests the service must refuse.
 */
final class Client {
    private final String origin;
    private final HttpClient http = HttpClient.newHttpClient();

    Client(String origin) {
        this.origin = origin;
    }

    void run() throws IOException, InterruptedException {
        try (SecretKey me = SecretKey.generate(); PublicKey mine = me.publicKey(); SecretKey thief = SecretKey.generate()) {
            HttpResponse<String> issued = send(HttpRequest.newBuilder(URI.create(origin + "/token"))
                    .POST(HttpRequest.BodyPublishers.ofString(mine.toPaserk())));
            String access = field(issued.body(), "access_token");
            String id = field(issued.body(), "id_token");
            report("POST /token", issued.statusCode(), "access " + prefix(access) + " (" + access.length()
                    + " chars), id " + prefix(id) + " (" + id.length() + " chars)");

            String published = send(HttpRequest.newBuilder(URI.create(origin + "/public-key")).GET()).body();
            try (PublicKey verifier = PublicKey.fromPaserk(published)) {
                String claims = Token.verify(verifier, id, new Rules().issuer(origin).audience("client"));
                System.out.println("id token verified with the published key: " + claims);
            }

            String target = origin + "/me?view=full";
            String proof = prove(me, target, access, "proof-1");
            report("GET /me with a proof", me(target, access, proof));
            report("GET /me, the same proof again", me(target, access, proof));
            report("GET /me without a proof", me(target, access, null));
            report("GET /me, proof for another path", me(target, access, prove(me, origin + "/admin", access, "proof-2")));
            report("GET /me, a tampered token", me(target, tamper(access), prove(me, target, access, "proof-3")));
            report("GET /me, stolen token, thief's proof", me(target, access, prove(thief, target, access, "proof-4")));
            report("GET /me with a new proof", me(target, access, prove(me, target, access, "proof-5")));
        }
    }

    private static String prove(SecretKey key, String target, String access, String jti) {
        return Holder.prove(key, "GET", target, null, access, jti, Instant.now().getEpochSecond(), 60);
    }

    private HttpResponse<String> me(String target, String access, String proof) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(target)).GET().header("Authorization", "CB2 " + access);
        if (proof != null) {
            request.header("CB2-Proof", proof);
        }
        return send(request);
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws IOException, InterruptedException {
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static void report(String what, HttpResponse<String> response) {
        String body = response.body();
        String shown = response.statusCode() == 200
                ? "sub " + field(body, "sub") + ", scope " + field(body, "scope")
                : field(body, "error");
        report(what, response.statusCode(), shown);
    }

    private static void report(String what, int status, String detail) {
        System.out.printf("%-40s %d  %s%n", what, status, detail);
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(name) + "\":\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : "?";
    }

    private static String prefix(String token) {
        int second = token.indexOf('.', token.indexOf('.') + 1);
        return token.substring(0, second);
    }

    private static String tamper(String token) {
        char last = token.charAt(token.length() - 1);
        return token.substring(0, token.length() - 1) + (last == 'A' ? 'B' : 'A');
    }
}
