import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

public class SecuritySampleTest {

    @Test
    public void shouldListAllProviders() {
        Arrays.asList(Security.getProviders()).forEach(provider -> {
            System.out.println(provider.getInfo());
        });
    }

    @Test
    public void shouldCreateAMessageDigest() throws NoSuchAlgorithmException {
        // given
        String hash = "89D22BCBBD63C76526E1D478AA0BA2F7B76FD902552E376547B6E9DD151B51B7";
        // and
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        // and
        String data = "ATMAN AND ROBIN";

        // when
        final byte[] digest = sha.digest(data.getBytes());


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
    public void shouldGenerateSignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // given
        String data = "ATMAN AND ROBIN";
        // and
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        final KeyPair keyPair = keyGen.generateKeyPair();
        // and
        Signature dsa = Signature.getInstance("SHA256withDSA");

        // WHEN
        /* Initializing the object with a private key */
        PrivateKey priv = keyPair.getPrivate();
        dsa.initSign(priv);

        /* Update and sign the data */
        dsa.update(data.getBytes());
        byte[] sig = dsa.sign();

        // THEN
        /* Initializing the object with the public key */
        PublicKey pub = keyPair.getPublic();
        dsa.initVerify(pub);

        /* Update and verify the data */
        dsa.update(data.getBytes());

        assertTrue(dsa.verify(sig));
    }

    @Test
    public void shouldLoadPrivateKey() throws Exception {
        // given
        String privateKeyPath = "src/main/resources/private_key.pem";

        // when
        final PrivateKey privateKey = getPrivateKey(privateKeyPath);

        // then
        assertNotNull(privateKey);
    }

    public PrivateKey getPrivateKey(String filename) throws Exception {

        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf =
                KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
}
