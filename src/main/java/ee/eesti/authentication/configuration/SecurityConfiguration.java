package ee.eesti.authentication.configuration;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.controller.HeartBeatController;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * OAuth security configuration
 * <p>
 * <p>
 * Note! Spring does seem to provide some default variables for oauth2 configuration.
 * <p>
 * Due to the lack of documentation, these standard variables might not work with different configurations.
 */
@Configuration
@Slf4j
@EnableWebSecurity(debug = true)
@PropertySources(@PropertySource(value = {"file:${tara-integration.properties}"}, ignoreResourceNotFound = true))
public class SecurityConfiguration {
    @Value("${frontpage.redirect.url}")
    private String frontPageRedirectUrl;
    @Value("${cors.allowedOrigins:*}")
    private String allowedOrigins;
    @Value("${headers.contentSecurityPolicy}")
    private String contentSecurityPolicy;
    @Value("${security.allowlist.jwt}")
    private String allowedJWTIps;

    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final CustomSessionAttributeSecurityFilter filter;
    private final JwtSignatureConfig jwtSignatureConfig;

    public SecurityConfiguration(JwtSignatureConfig jwtSignatureConfig,
                                 AuthenticationSuccessHandler authenticationSuccessHandler,
                                 CustomSessionAttributeSecurityFilter filter,
                                 @Lazy OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {
        this.jwtSignatureConfig = jwtSignatureConfig;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.filter = filter;
        this.accessTokenResponseClient = accessTokenResponseClient;
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .disable())
                .cors(Customizer.withDefaults())
                .headers(header -> header.contentSecurityPolicy(csp -> csp.policyDirectives(contentSecurityPolicy)))
                .authorizeRequests(auth ->
                    auth.requestMatchers("/v2/api-docs",
                            "/swagger-resources/configuration/ui",
                            "/swagger-resources",
                            "/swagger-resources/configuration/security",
                            "/swagger-ui.html",
                            "/webjars/**",
                            HeartBeatController.URL)
                        .permitAll()
                        .requestMatchers("/cancel-auth")
                        .permitAll()
                        .requestMatchers("/jwt/custom-jwt-generate",
                            "/jwt/custom-jwt-userinfo",
                            "/jwt/change-jwt-role")
                        .access(getAllowedIps())
                        .requestMatchers("/jwt/**")
                        .permitAll()
                        .requestMatchers("/**").authenticated())
                    .logout(logoutUrl ->
                        logoutUrl.logoutUrl("/logout")
                            .logoutSuccessUrl(frontPageRedirectUrl))
                    .addFilterBefore(filter, OAuth2AuthorizationRequestRedirectFilter.class)
                    .oauth2Login(oauth ->
                        oauth.loginPage(frontPageRedirectUrl)
                            .redirectionEndpoint(Customizer.withDefaults())
                            .authorizationEndpoint(aep -> aep
                                .baseUri("/authenticate"))
                                .tokenEndpoint(aot -> aot.accessTokenResponseClient(accessTokenResponseClient))
                            .successHandler(authenticationSuccessHandler));
        return http.build();
    }

    private String getAllowedIps() {
        return Arrays.stream(allowedJWTIps.split(",")).reduce("", (partialString, element) -> {
            if (partialString.equals("")) {
                return partialString + String.format("hasIpAddress('%s')", element);
            }
            return partialString + " or " + String.format("hasIpAddress('%s')", element);
        });
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        return new DefaultAuthorizationCodeTokenResponseClient();
    }


    @Bean
    public JWSSigner rsassaSigner() {

        try {

            return new RSASSASigner(
                    JwtUtils.getJwtSignKeyFromKeystore(
                            jwtSignatureConfig.getKeyStoreType(),
                            jwtSignatureConfig.getKeyStore().getInputStream(),
                            jwtSignatureConfig.getKeyStorePassword().toCharArray(),
                            jwtSignatureConfig.getKeyAlias()));

        } catch (Exception e) {
            log.error("Unable to initialize RSASSASigner ", e);
            throw new IllegalArgumentException("RSASSASigner not initialized, check configuration properties with prefix jwt-integration.signature");
        }
    }

    @Bean
    public JWSVerifier jwsVerifier() {
        try {
            return new RSASSAVerifier(
                    JwtUtils.getJwtSignKeyFromKeystore(
                            jwtSignatureConfig.getKeyStoreType(),
                            jwtSignatureConfig.getKeyStore().getInputStream(),
                            jwtSignatureConfig.getKeyStorePassword().toCharArray(),
                            jwtSignatureConfig.getKeyAlias()));
        } catch (Exception e) {
            log.error("Unable to initialize RSSASSAVerifier", e);
            throw new IllegalArgumentException(e);
        }
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
