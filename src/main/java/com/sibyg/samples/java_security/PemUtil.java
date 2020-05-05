package com.sibyg.samples.java_security;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class PemUtil {

    public static PemObject pemObject(String filePath) throws IOException {
        try (PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(filePath)))) {
            return pemReader.readPemObject();
        }
    }

    public static PrivateKey generatePrivateKey(String filePath, KeyFactory factory) throws InvalidKeySpecException, IOException {
        return factory.generatePrivate(new PKCS8EncodedKeySpec(pemObject(filePath).getContent()));
    }

    public static PublicKey generatePublicKey(String filePath, KeyFactory factory) throws InvalidKeySpecException, IOException {
        return factory.generatePublic(new X509EncodedKeySpec(pemObject(filePath).getContent()));
    }
}