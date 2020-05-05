package com.sibyg.samples.java_security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecuritySampleTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecuritySampleTest.class);

    @Test
    public void shouldListAllProviders() {
        Arrays.asList(Security.getProviders()).forEach(provider -> {
            LOGGER.info(provider.getInfo());
        });
    }

    @Test
    public void shouldCreateAMessageDigest() throws NoSuchAlgorithmException {
        // given
        String hash = givenHash();
        // and
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        // and
        String data = givenData();

        // when
        final byte[] digest = sha.digest(data.getBytes());


        // then
        assertEquals(DatatypeConverter.printHexBinary(digest), hash);
    }

    @Test
    public void shouldCreateKeyPairGenerator() throws NoSuchAlgorithmException {
        // given
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");

        // when
        final KeyPair keyPair = keyGen.generateKeyPair();

        // then
        assertNotNull(keyPair.getPrivate());
        // and
        assertNotNull(keyPair.getPublic());
    }

    @Test
    public void shouldLoadPrivateKey() throws Exception {
        // given
        String privateKeyPath = givenPrivateKeyPath();
        // and
        addBouncyCastleAsSecurityProvider();

        // when
        PrivateKey privateKey = PemUtil.generatePrivateKey(privateKeyPath, rsaKeyFactoryFromBouncyCastle());
        LOGGER.info(String.format("Instantiated private key: %s", privateKey));
        // and
        assertNotNull(privateKey);
    }

    private KeyFactory rsaKeyFactoryFromBouncyCastle() throws NoSuchAlgorithmException, NoSuchProviderException {
        return KeyFactory.getInstance("RSA", "BC");
    }

    @Test
    public void shouldLoadPublicKey() throws Exception {
        // given
        String publicKeyPath = givenPublicFilePath();
        // and
        addBouncyCastleAsSecurityProvider();
        // and
        KeyFactory factory = rsaKeyFactoryFromBouncyCastle();

        // when
        PublicKey publicKey = PemUtil.generatePublicKey(publicKeyPath, factory);
        LOGGER.info(String.format("Instantiated public key: %s", publicKey));

        // and
        assertNotNull(publicKey);
    }

    private String givenPublicFilePath() {
        return "src/main/resources/public_key.pem";
    }

    @Test
    public void shouldGenerateSignature() throws Exception {
        // given
        String data = givenData();

        // and
        Signature sha256withRSASignature = sha256withRSASignature();

        // and initializing the object with a private key
        sha256withRSASignature.initSign(givenPrivateKey(givenPrivateKeyPath()));

        // and update and sign the data
        sha256withRSASignature.update(data.getBytes());
        byte[] signature = sha256withRSASignature.sign();

        // then
        assertNotNull(signature);
    }

    @Test
    public void shouldValidateSignature() throws Exception {
        // given
        String data = givenData();

        // and
        Signature sha256withRSASignature = sha256withRSASignature();

        // and initializing the object with a private key
        sha256withRSASignature.initSign(givenPrivateKey(givenPrivateKeyPath()));

        // and update and sign the data
        sha256withRSASignature.update(data.getBytes());
        byte[] signature = sha256withRSASignature.sign();

        // when
        // initializing the object with the public key
        sha256withRSASignature.initVerify(givenPublicKey(givenPublicFilePath()));

        // and, update and verify the data */
        sha256withRSASignature.update(data.getBytes());

        // then
        assertTrue(sha256withRSASignature.verify(signature));
    }

    private String givenPrivateKeyPath() {
        return "src/main/resources/private_key.pem";
    }

    private String givenHash() {
        return "89D22BCBBD63C76526E1D478AA0BA2F7B76FD902552E376547B6E9DD151B51B7";
    }

    private String givenData() {
        return "ATMAN AND ROBIN";
    }

    private Signature sha256withRSASignature() throws NoSuchAlgorithmException {
        return Signature.getInstance("SHA256withRSA");
    }

    private Signature sha256withDSASignature() throws NoSuchAlgorithmException {
        return Signature.getInstance("SHA256withDSA");
    }

    private void addBouncyCastleAsSecurityProvider() {
        Security.addProvider(new BouncyCastleProvider());
        LOGGER.info("BouncyCastle provider added.");
    }

    private PrivateKey givenPrivateKey(String privateKeyPath) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        addBouncyCastleAsSecurityProvider();
        return PemUtil.generatePrivateKey(privateKeyPath, rsaKeyFactoryFromBouncyCastle());
    }

    private PublicKey givenPublicKey(String publicKeyPath) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        addBouncyCastleAsSecurityProvider();
        return PemUtil.generatePublicKey(publicKeyPath, rsaKeyFactoryFromBouncyCastle());
    }
}