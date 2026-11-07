package com.cipherbird.cb2.example.service;

import com.cipherbird.cb2.Cb2;
import java.net.InetSocketAddress;

/**
 * Starts the token service on a free port of 127.0.0.1, runs the client
 * against it over real HTTP, prints what happened, and stops.
 */
public final class TokenService {
    private TokenService() {
    }

    /**
     * Runs the example.
     *
     * @param args unused
     * @throws Exception when the service cannot start or a request fails
     */
    public static void main(String[] args) throws Exception {
        if (!Cb2.hasPublic()) {
            System.out.println("this cb2 build has no cb2.public; the example needs it");
            return;
        }
        System.out.println("cb2 " + Cb2.version() + " from Java");
        try (Server server = new Server(new InetSocketAddress("127.0.0.1", 0))) {
            System.out.println("token service listening on " + server.origin());
            new Client(server.origin()).run();
        }
    }
}
