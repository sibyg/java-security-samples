package com.sibyg.samples.java_security.api;

import static com.sibyg.samples.java_security.util.PemUtil.privateKey;
import static com.sibyg.samples.java_security.util.PemUtil.publicKey;
import static com.sibyg.samples.java_security.util.PemUtil.rsaKeyFactoryFromBouncyCastle;
import static com.sibyg.samples.java_security.util.PemUtil.sha256withRSASignature;

import java.security.Signature;

import com.sibyg.samples.java_security.Form3Config;
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
    public String greeting(@RequestParam(value = "data", defaultValue = "World") String data) {

        log.info("PUBLIC KEY:{}, PRIVATE KEY:{}", form3Config.getPublicKey(), form3Config.getPrivateKey());

        try {
            // given
            Signature sha256withRSASignature = sha256withRSASignature();

            // and initializing the object with a private key
            sha256withRSASignature.initSign(privateKey(form3Config.getPrivateKey(), rsaKeyFactoryFromBouncyCastle()));

            // and update and sign the data
            sha256withRSASignature.update(data.getBytes());
            byte[] signature = sha256withRSASignature.sign();

            // when
            // initializing the object with the public key
            sha256withRSASignature.initVerify(publicKey(form3Config.getPublicKey(), rsaKeyFactoryFromBouncyCastle()));

            // and, update and verify the data */
            sha256withRSASignature.update(data.getBytes());

            // then
            return "VERIFY:" + sha256withRSASignature.verify(signature);
        } catch (Exception e) {
            log.error("ERROR: unable to validate message", e);
        }

        return "DEFAULT: false";
    }
}