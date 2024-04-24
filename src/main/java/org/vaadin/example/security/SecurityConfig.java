package org.vaadin.example.security;

import com.vaadin.flow.spring.security.VaadinAwareSecurityContextHolderStrategy;
import com.vaadin.flow.spring.security.VaadinSavedRequestAwareAuthenticationSuccessHandler;
import com.vaadin.flow.spring.security.VaadinWebSecurity;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * This class sets up Spring Security to protect our application.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
class SecurityConfig extends VaadinWebSecurity {

    @Autowired
    final ClientRegistrationRepository clientRegistrationRepository;
    final GrantedAuthoritiesMapper authoritiesMapper;

    SecurityConfig(ClientRegistrationRepository clientRegistrationRepository,
                   GrantedAuthoritiesMapper authoritiesMapper) {
        System.out.println("S.........SecurityConfig");
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authoritiesMapper = authoritiesMapper;
        SecurityContextHolder.setStrategyName(VaadinAwareSecurityContextHolderStrategy.class.getName());
        System.out.println("E.........SecurityConfig");
    }

    @Bean
    public SessionRepository sessionRepository() {
        System.out.println(".........sessionRepository");
        return new SessionRepository();
    }

    @Bean
    public ServletListenerRegistrationBean<SessionRepositoryListener> sessionRepositoryListener() {
        var bean = new ServletListenerRegistrationBean<SessionRepositoryListener>();
        bean.setListener(new SessionRepositoryListener(sessionRepository()));
        System.out.println(".........sessionRepositoryListener");
        return bean;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        System.out.println(".........configure");
        super.configure(http);
        http
                // Enable OAuth2 login
                .oauth2Login(oauth2Login ->
                        oauth2Login
                                .clientRegistrationRepository(clientRegistrationRepository)
                                .userInfoEndpoint(userInfoEndpoint ->
                                        userInfoEndpoint
                                                // Use a custom authorities mapper to get the roles from the identity provider into the Authentication token
                                                .userAuthoritiesMapper(authoritiesMapper)
                                )
                             //   .loginPage("/login")
                                // Use a Vaadin aware authentication success handler
                                .successHandler(new VaadinSavedRequestAwareAuthenticationSuccessHandler())
                                .failureUrl("/login?error")
                )
                // Configure logout
                .logout(logout ->
                        logout
                                // Enable OIDC logout (requires that we use the 'openid' scope when authenticating)
                                .logoutSuccessHandler(logoutSuccessHandler())
                                // When CSRF is enabled, the logout URL normally requires a POST request with the CSRF
                                // token attached. This makes it difficult to perform a logout from within a Vaadin
                                // application (since Vaadin uses its own CSRF tokens). By changing the logout endpoint
                                // to accept GET requests, we can redirect to the logout URL from within Vaadin.
                                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                );
    }

    private OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler() {
        System.out.println(".........logoutSuccessHandler");
        var logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/logged-out");
        return logoutSuccessHandler;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        System.out.println(".........configure.....web");
        super.configure(web);
        // Don't apply security rules on our static pages
        // /back-channel-logout should only be accessible from certain hosts/IPs. In this case we assume this has
        // been taken care of in a firewall outside this application.
       // web.ignoring().antMatchers("/logged-out", "/session-expired", "/back-channel-logout");
        web.ignoring().requestMatchers(new AntPathRequestMatcher("/images/*.png"));
    }

    @Bean
    public PolicyFactory htmlSanitizer() {
        System.out.println(".........htmlSanitizer");
        // This is the policy we will be using to sanitize HTML input
        return Sanitizers.FORMATTING.and(Sanitizers.BLOCKS).and(Sanitizers.STYLES).and(Sanitizers.LINKS);
    }
}