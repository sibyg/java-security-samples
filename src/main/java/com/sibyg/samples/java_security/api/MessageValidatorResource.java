package com.sibyg.samples.java_security.api;

import static com.sibyg.samples.java_security.util.PemUtil.privateKey;
import static com.sibyg.samples.java_security.util.PemUtil.publicKey;
import static com.sibyg.samples.java_security.util.PemUtil.rsaKeyFactoryFromBouncyCastle;
import static com.sibyg.samples.java_security.util.PemUtil.sha256withRSASignature;

import java.io.IOException;
import java.security.Signature;

import com.sibyg.samples.java_security.Form3Config;
import com.sibyg.samples.java_security.util.FileUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class MessageValidatorResource {

    @Autowired
    private Form3Config form3Config;

    @GetMapping("/validate")
    public String validate(@RequestParam(value = "data", defaultValue = "World") String data) throws IOException {

          log.info("Public Key Location:{}, Private Key Location:{}", form3Config.getPublicKeyLocation(), form3Config.getPrivateKeyLocation());

        if (!FileUtil.readFileToString(form3Config.getPublicKeyLocation()).isPresent()) {
            return "PUBLIC_KEY_NOT_PRESENT:" + form3Config.getPublicKeyLocation();
        }

        if (!FileUtil.readFileToString(form3Config.getPrivateKeyLocation()).isPresent()) {
            return "PRIVATE_KEY_NOT_PRESENT:" + form3Config.getPrivateKeyLocation();
        }

        String publicKeyContent = FileUtil.readFileToString(form3Config.getPublicKeyLocation()).get();// form3Config.getPublicKey();
        String privateKeyContent = FileUtil.readFileToString(form3Config.getPrivateKeyLocation()).get(); // form3Config.getPrivateKey();

        log.info("PUBLIC KEY:{}, PRIVATE KEY:{}", publicKeyContent, privateKeyContent);

        try {
            // given
            Signature sha256withRSASignature = sha256withRSASignature();

            // and initializing the object with a private key
            sha256withRSASignature.initSign(privateKey(privateKeyContent, rsaKeyFactoryFromBouncyCastle()));

            // and update and sign the data
            sha256withRSASignature.update(data.getBytes());
            byte[] signature = sha256withRSASignature.sign();

            // when
            // initializing the object with the public key
            sha256withRSASignature.initVerify(publicKey(publicKeyContent, rsaKeyFactoryFromBouncyCastle()));

            // and, update and verify the data */
            sha256withRSASignature.update(data.getBytes());

            // then
            return "VERIFY(v5):" + sha256withRSASignature.verify(signature);
        } catch (Exception e) {
            log.error("ERROR: unable to validate message", e);
        }

        return "DEFAULT: false";
    }
}