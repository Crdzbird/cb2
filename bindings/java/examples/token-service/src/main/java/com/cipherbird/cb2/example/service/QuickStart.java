package com.cipherbird.cb2.example.service;

import com.cipherbird.cb2.Cb2;
import com.cipherbird.cb2.Cb2Exception;
import com.cipherbird.cb2.LocalKey;
import com.cipherbird.cb2.PublicKey;
import com.cipherbird.cb2.Rules;
import com.cipherbird.cb2.SecretKey;
import com.cipherbird.cb2.Token;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** The quick start of the README: a cb2.local token, a refusal, and a cb2.public token. */
public final class QuickStart {
    private QuickStart() {
    }

    /**
     * Runs the quick start.
     *
     * @param args unused
     */
    public static void main(String[] args) {
        String claims = "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"sub\":\"user-1\","
                + "\"exp\":\"2099-01-01T00:00:00+00:00\",\"jti\":\"id-1\"}";
        Set<String> seen = ConcurrentHashMap.newKeySet();
        Rules rules = new Rules()
                .issuer("https://issuer.example")
                .audience("api")
                .replay(seen::add);

        try (LocalKey key = LocalKey.generate()) {
            String token = Token.seal(key, claims);
            System.out.println("cb2.local token: " + token.length() + " chars");
            System.out.println("opened:          " + Token.open(key, token, rules));
            try {
                Token.open(key, token, rules);
            } catch (Cb2Exception e) {
                System.out.println("opened again:    refused, " + e.name());
            }
        }

        if (Cb2.hasPublic()) {
            try (SecretKey signer = SecretKey.generate(); PublicKey verifier = signer.publicKey()) {
                String token = Token.sign(signer, claims);
                Rules check = new Rules().issuer("https://issuer.example").audience("api");
                System.out.println("cb2.public token: " + token.length() + " chars");
                System.out.println("verified:         " + Token.verify(verifier, token, check));
            }
        }
    }
}
