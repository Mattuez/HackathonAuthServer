package com.example.authserverhackathon.authorizationServer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class JwtCustomClaimsTokenEnhancer {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            Authentication authentication = context.getPrincipal();
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

            if (authentication.getPrincipal() instanceof AuthUser authUser) {
                context.getClaims().claim("user_id", authUser.getUserId());
            }

            // Mapeia as GrantedAuthority para uma lista de strings contendo os nomes das permissões
            List<String> permissionNames = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            // Adiciona a lista de permissões como uma claim "authorities"
            context.getClaims().claim("authorities", permissionNames);
        };
    }
}
