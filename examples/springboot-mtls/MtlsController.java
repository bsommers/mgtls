package com.example.mgtls;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.autoconfigure.web.client.RestClientSsl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

/**
 * Spring Boot 3.2+ Mutual TLS Controller & Security Configuration for mgtls.
 */
@RestController
@RequestMapping("/api/v1/mtls")
public class MtlsController {

    private static final String X509_ATTR = "jakarta.servlet.request.X509Certificate";

    @GetMapping("/whoami")
    public Map<String, Object> whoami(HttpServletRequest request, Principal principal) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(X509_ATTR);
        if (certs == null || certs.length == 0) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Client X.509 certificate missing from servlet request"
            );
        }

        X509Certificate leaf = certs[0];
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("authenticated", true);
        response.put("principal", principal != null ? principal.getName() : leaf.getSubjectX500Principal().getName());
        response.put("subjectDn", leaf.getSubjectX500Principal().getName());
        response.put("issuerDn", leaf.getIssuerX500Principal().getName());
        response.put("serialHex", leaf.getSerialNumber().toString(16));
        response.put("notBefore", leaf.getNotBefore().toInstant().toString());
        response.put("notAfter", leaf.getNotAfter().toInstant().toString());
        response.put("chainLength", certs.length);
        return response;
    }

    @Configuration
    @EnableMethodSecurity
    public static class MtlsSecurityConfiguration {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                .csrf(csrf -> csrf.disable())
                .x509(x509 -> x509
                    .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                    .userDetailsService(mtlsUserDetailsService())
                )
                .authorizeHttpRequests(auth -> auth
                    .anyRequest().authenticated()
                );
            return http.build();
        }

        @Bean
        public UserDetailsService mtlsUserDetailsService() {
            return username -> new User(
                username,
                "",
                AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_MTLS_CLIENT")
            );
        }

        @Bean
        public RestClient mtlsRestClient(RestClient.Builder builder, RestClientSsl ssl) {
            return builder
                .baseUrl("https://localhost:8443")
                .apply(ssl.fromBundle("mtls-client"))
                .build();
        }
    }
}
