package com.cipherbird.cb2.bench;

import com.cipherbird.cb2.Cb2;

/** Prints the size in bytes of the token each benchmark makes from the same claims. */
public final class TokenSizes {
    private TokenSizes() {
    }

    /**
     * Prints the sizes.
     *
     * @param args unused
     * @throws Exception when a token cannot be made
     */
    public static void main(String[] args) throws Exception {
        Cb2Bench cb2 = new Cb2Bench();
        cb2.setup();
        JjwtBench jjwt = new JjwtBench();
        jjwt.setup();
        NimbusBench nimbus = new NimbusBench();
        nimbus.setup();
        Paseto4jBench paseto = new Paseto4jBench();
        paseto.setup();
        System.out.println("claims JSON (cb2 and PASETO payload): " + Claims.json().length() + " bytes");
        print("cb2.local", cb2.localSeal());
        print("cb2.public (Ed25519 + ML-DSA-65)", cb2.publicSign());
        print("cb3.local (compact)", cb2.compactLocalSeal());
        print("cb3.public (compact)", cb2.compactPublicSign());
        print("JJWT HS256", jjwt.hs256Sign());
        print("JJWT EdDSA", jjwt.eddsaSign());
        print("JJWT ES256", jjwt.es256Sign());
        print("Nimbus HS256", nimbus.hs256Sign());
        print("Nimbus EdDSA", nimbus.eddsaSign());
        print("Nimbus ES256", nimbus.es256Sign());
        print("PASETO v4.local (paseto4j)", paseto.localEncrypt());
        print("PASETO v4.public (paseto4j)", paseto.publicSign());
        cb2.tearDown();
        System.out.println("cb2 " + Cb2.version());
    }

    private static void print(String what, String token) {
        System.out.printf("%-36s %6d bytes%n", what, token.length());
    }
}
