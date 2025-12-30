package ee.eesti.authentication.security;

import ee.eesti.authentication.configuration.AuthenticationRequestProperties;
import ee.eesti.authentication.configuration.OAuthGatewayProperties;
import ee.eesti.authentication.configuration.OAuthSecurityProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;

import static ee.eesti.authentication.session.SessionContext.SESSION_LOGIN_REDIRECT;
import static ee.eesti.authentication.session.SessionContext.SESSION_USER_AGENT;

@Slf4j
@Component
public class CustomAuthenticationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final OAuthGatewayProperties oAuthGatewayProperties;
    private final OAuthSecurityProperties oAuthSecurityProperties;
    private final AuthenticationRequestProperties authenticationRequestProperties;
    private final OAuth2AuthorizationRequestResolver delegate;

    public CustomAuthenticationRequestResolver(
            OAuthGatewayProperties oAuthGatewayProperties,
            OAuthSecurityProperties oAuthSecurityProperties,
            AuthenticationRequestProperties authenticationRequestProperties,
            ClientRegistrationRepository clientRegistrationRepository
    ) {
        this.oAuthGatewayProperties = oAuthGatewayProperties;
        this.oAuthSecurityProperties = oAuthSecurityProperties;
        this.authenticationRequestProperties = authenticationRequestProperties;
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                "/sso/oauth2/authorization"
        );
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authRequest = delegate.resolve(request);
        if (authRequest == null) {
            return null;
        }
        saveRedirectUri(request);
        saveUserAgent(request);
        return customizeAuthRequest(request, authRequest);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest authRequest = delegate.resolve(request, clientRegistrationId);
        if (authRequest == null) {
            return null;
        }
        saveRedirectUri(request);
        saveUserAgent(request);
        return customizeAuthRequest(request, authRequest);
    }

    private OAuth2AuthorizationRequest customizeAuthRequest(HttpServletRequest request, OAuth2AuthorizationRequest authRequest) {
        return OAuth2AuthorizationRequest.from(authRequest)
                .additionalParameters(params -> {
                    authenticationRequestProperties.getPropagatedQueryParams()
                            .forEach(queryParamKey -> {
                                var value = request.getParameter(queryParamKey);
                                if (value == null) {
                                    value = authenticationRequestProperties.getDefaultQueryParams().get(queryParamKey);
                                }
                                if (value != null) {
                                    params.put(queryParamKey, value);
                                }
                            });
                    authenticationRequestProperties.getDefaultQueryParams()
                            .forEach((key, value) -> {
                                if (!params.containsKey(key)) {
                                    params.put(key, value);
                                }
                            });
                })
                .build();
    }

    private void saveRedirectUri(HttpServletRequest request) {
        var redirectUri = request.getParameter("redirect_uri");
        var session = request.getSession();
        if (redirectUri != null && isAllowedRedirectUri(redirectUri)) {
            session.setAttribute(SESSION_LOGIN_REDIRECT, redirectUri);
        } else {
            session.setAttribute(SESSION_LOGIN_REDIRECT, oAuthGatewayProperties.getUri().getLoginRedirectFallback());
        }
    }

    private void saveUserAgent(HttpServletRequest request) {
        if (!oAuthSecurityProperties.userAgent().enabled()) {
            return;
        }
        var userAgentHeaders = Collections.list(request.getHeaders(HttpHeaders.USER_AGENT));
        if (userAgentHeaders.isEmpty()) {
            log.warn("No user-agent found in request");
            return;
        }
        request.getSession().setAttribute(SESSION_USER_AGENT, new ArrayList<>(userAgentHeaders));
    }

    private boolean isAllowedRedirectUri(String uri) {
        return oAuthGatewayProperties.getRedirectUri().getWhitelist().stream()
                .anyMatch(uri::matches);
    }
}