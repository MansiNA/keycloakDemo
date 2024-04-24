package org.vaadin.example.security.keycloak;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.vaadin.example.security.SessionRepository;

import java.util.Optional;

/**
 * A REST controller that receives back channel logout requests from Keycloak. Back Channel logout is coming into
 * Spring Security in the future (https://github.com/spring-projects/spring-security/issues/7845) so this is a quick
 * and dirty implementation.
 */
@RestController
class KeycloakBackChannelLogoutController {

    private final JwtDecoder jwtDecoder;
    private final SessionRepository sessionRepository;

    KeycloakBackChannelLogoutController(ClientRegistrationRepository clientRegistrationRepository,
                                        SessionRepository sessionRepository) {

        System.out.println("S.........KeycloakBackChannelLogoutController");
        this.sessionRepository = sessionRepository;
        var jwkSetUri = clientRegistrationRepository.findByRegistrationId("keycloak").getProviderDetails().getJwkSetUri();
        jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        System.out.println("E.........KeycloakBackChannelLogoutController");
    }

    @PostMapping("/back-channel-logout")
    public void logout(@RequestParam("logout_token") String rawLogoutToken) {
        System.out.println(".........logout");
        var logoutToken = jwtDecoder.decode(rawLogoutToken);
        var sessionId = logoutToken.getClaimAsString("sid");
        invalidateSession(sessionId);
    }

    private void invalidateSession(String keycloakSessionId) {
        System.out.println(".........invalidateSession");
        sessionRepository.invalidate(session ->
                extractSecurityContext(session)
                        .map(SecurityContext::getAuthentication)
                        .filter(auth -> correspondsToSession(auth, keycloakSessionId))
                        .isPresent()
        );
    }

    private Optional<SecurityContext> extractSecurityContext(HttpSession session) {
        System.out.println(".........extractSecurityContext");
        return Optional.ofNullable((SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));
    }

    private boolean correspondsToSession(Authentication authentication, String keycloakSessionId) {
        System.out.println(".........correspondsToSession");
        if (authentication instanceof OAuth2AuthenticationToken) {
            return keycloakSessionId.equals(((OAuth2AuthenticationToken) authentication).getPrincipal().getAttribute("sid"));
        }
        return false;
    }
}