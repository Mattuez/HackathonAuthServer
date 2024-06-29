package com.example.authserverhackathon.authorizationServer;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@Validated
@Getter
@Setter
@ConfigurationProperties("hackathon.jwt.keystore")
public class JwtKeyStoreProperties {

    @NotNull
    private String resource;

    @NotNull
    private String keyPass;

    @NotNull
    private String storePass;

    @NotNull
    private String alias;
}
