package com.example.authserverhackathon.openapi;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(info = @Info(title = "Authorization Server API", version = "v1"))
@SecurityScheme(
        name = "oauth2",
        type = SecuritySchemeType.OAUTH2,
        in = SecuritySchemeIn.HEADER,
        flows = @OAuthFlows(
                clientCredentials = @OAuthFlow(
                        tokenUrl = "http://localhost:8081/oauth2/token",
                        scopes = {
                                @OAuthScope(name = "READ", description = "read scope"),
                                @OAuthScope(name = "WRITE", description = "write scope")
                        }
                ),
                authorizationCode = @OAuthFlow(
                        authorizationUrl = "http://localhost:8081/oauth2/authorize",
                        tokenUrl = "http://localhost:8081/oauth2/token",
                        scopes = {
                                @OAuthScope(name = "READ", description = "read scope"),
                                @OAuthScope(name = "WRITE", description = "write scope")
                        }
                )
        )
)
public class OpenApiConfig {

}
