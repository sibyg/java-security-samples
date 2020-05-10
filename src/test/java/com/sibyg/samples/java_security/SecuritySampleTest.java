package com.sibyg.samples.java_security;

import static com.sibyg.samples.java_security.util.FileUtil.readFileToString;
import static com.sibyg.samples.java_security.util.PemUtil.privateKey;
import static com.sibyg.samples.java_security.util.PemUtil.publicKey;
import static com.sibyg.samples.java_security.util.PemUtil.rsaKeyFactoryFromBouncyCastle;
import static com.sibyg.samples.java_security.util.PemUtil.sha256withRSASignature;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import com.sibyg.samples.java_security.util.PemUtil;
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
        // when
        PrivateKey privateKey = privateKey(readFileToString("form3/private_key.pem").get(), rsaKeyFactoryFromBouncyCastle());
        LOGGER.info(String.format("Instantiated private key: %s", privateKey));
        // and
        assertNotNull(privateKey);
    }

    @Test
    public void shouldLoadPublicKey() throws Exception {
        // when
        PublicKey publicKey = PemUtil.publicKey(readFileToString("form3/public_key.pem").get(), rsaKeyFactoryFromBouncyCastle());
        LOGGER.info(String.format("Instantiated public key: %s", publicKey));

        // and
        assertNotNull(publicKey);
    }

    @Test
    public void shouldGenerateSignature() throws Exception {
        // given
        String data = givenData();

        // and
        Signature sha256withRSASignature = sha256withRSASignature();

        // and initializing the object with a private key
        sha256withRSASignature.initSign(privateKey(readFileToString("form3/private_key.pem").get(), rsaKeyFactoryFromBouncyCastle()));

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
        sha256withRSASignature.initSign(privateKey(readFileToString("form3/private_key.pem").get(), rsaKeyFactoryFromBouncyCastle()));

        // and update and sign the data
        sha256withRSASignature.update(data.getBytes());
        byte[] signature = sha256withRSASignature.sign();

        // when
        // initializing the object with the public key
        sha256withRSASignature.initVerify(publicKey(readFileToString("form3/public_key.pem").get(), rsaKeyFactoryFromBouncyCastle()));

        // and, update and verify the data */
        sha256withRSASignature.update(data.getBytes());

        // then
        assertTrue(sha256withRSASignature.verify(signature));
    }


    private String givenHash() {
        return "89D22BCBBD63C76526E1D478AA0BA2F7B76FD902552E376547B6E9DD151B51B7";
    }

    private String givenData() {
        return "ATMAN AND ROBIN";
    }
}