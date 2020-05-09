package com.sibyg.samples.java_security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "form3")
@Data
public class Form3Config {
    private String publicKey;
    private String privateKey;
}
