package com.sibyg.samples.java_security.util;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class PemUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static Signature sha256withRSASignature() throws NoSuchAlgorithmException {
        return Signature.getInstance("SHA256withRSA");
    }

    public static Signature sha256withDSASignature() throws NoSuchAlgorithmException {
        return Signature.getInstance("SHA256withDSA");
    }

    public static KeyFactory rsaKeyFactoryFromBouncyCastle() throws NoSuchAlgorithmException, NoSuchProviderException {
        return KeyFactory.getInstance("RSA", "BC");
    }

    public static PemObject pemObject(String keyContent) throws IOException {
        try (PemReader pemReader = new PemReader(new StringReader(keyContent))) {
            return pemReader.readPemObject();
        }
    }

    public static PrivateKey privateKey(String keyContent, KeyFactory factory) throws InvalidKeySpecException, IOException {
        return factory.generatePrivate(new PKCS8EncodedKeySpec(pemObject(keyContent).getContent()));
    }

    public static PublicKey publicKey(String keyContent, KeyFactory factory) throws InvalidKeySpecException, IOException {
        return factory.generatePublic(new X509EncodedKeySpec(pemObject(keyContent).getContent()));
    }
}