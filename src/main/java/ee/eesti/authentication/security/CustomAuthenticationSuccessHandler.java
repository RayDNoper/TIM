package ee.eesti.authentication.security;

import ee.eesti.authentication.configuration.OAuthGatewayProperties;
import ee.eesti.authentication.configuration.OAuthSecurityProperties;
import ee.eesti.authentication.exception.ErrorCode;
import ee.eesti.authentication.exception.LogoutWithErrorCodeException;
import ee.eesti.authentication.service.SessionUtil;
import ee.eesti.authentication.service.SsoResolver;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

import java.io.IOException;
import java.net.URI;
import java.util.stream.StreamSupport;

import static ee.eesti.authentication.session.SessionContext.SESSION_LOGIN_REDIRECT;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  private final OAuth2AuthorizedClientManager clientManager;
  private final OAuth2AuthorizedClientRepository authorizedClientRepository;
  private final OAuthGatewayProperties oAuthGatewayProperties;
  private final OAuthSecurityProperties oAuthSecurityProperties;
  private final RedisOidcSessionRegistry sessionRegistry;
  private final SsoResolver ssoResolver;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request,
                                      HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {
    if (log.isTraceEnabled()) {
      log.trace("Login success: principal={}", authentication.getPrincipal());
    } else {
      log.debug("Login success");
    }

    HttpSession session = request.getSession();
    handleAuthenticationSuccess(request, response, authentication, session);
  }

  private void handleAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                           Authentication authentication, HttpSession session) throws IOException {
    if (log.isTraceEnabled()) {
      log.trace("Session created: session id hash={}", SessionUtil.getHashCodeFromSessionId(session.getId()));
    } else {
      log.debug("Session created");
    }

    String redirect = (String) session.getAttribute(SESSION_LOGIN_REDIRECT);
    session.removeAttribute(SESSION_LOGIN_REDIRECT);

    try {
      if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
        validate(request, oidcUser);
        saveSession(session, oidcUser);
      }

      authorize(request, response, authentication);

      String redirectUri = redirect != null ? redirect : oAuthGatewayProperties.getUri().getLoginRedirectFallback();
      response.sendRedirect(redirectUri);

    } catch (LogoutWithErrorCodeException ex) {
      String redirectUri = oAuthGatewayProperties.getUri().getLogoutRedirectFallback() + "?errorCode=" + ex.getErrorCode();
      response.sendRedirect(redirectUri);
    }
  }

  private void validate(HttpServletRequest request, OidcUser oidcUser) {
    var amr = oidcUser.getClaim("amr");
    if (amr instanceof Iterable<?> amrIterable) {
      validateIterableAmr(request, amrIterable);
    } else if (amr instanceof String amrString) {
      validateStringAmr(request, amrString);
    } else {
      invalidateLoginAttempt(request);
    }
  }

  private void saveSession(HttpSession session, OidcUser oidcUser) {
    String sid = oidcUser.getClaimAsString("sid");
    OidcSessionInformation existingSession = sessionRegistry.removeSessionInformation(sid);
    if (existingSession != null) {
      OidcSessionInformation updatedSession = existingSession.withSessionId(session.getId());
      sessionRegistry.saveSessionInformation(updatedSession);
    }
  }

  private OAuth2AuthorizedClient authorize(HttpServletRequest request, HttpServletResponse response,
                                           Authentication authentication) {
    OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
            .withClientRegistrationId(ssoResolver.resolve(request))
            .principal(authentication)
            .attribute(HttpServletRequest.class.getName(), request)
            .attribute(HttpServletResponse.class.getName(), response)
            .build();

    OAuth2AuthorizedClient authorizedClient = clientManager.authorize(authorizeRequest);

    if (authorizedClient != null) {
      authorizedClientRepository.saveAuthorizedClient(authorizedClient, authentication, request, response);
      log.debug("Authorized client saved: accessToken expiresAt={}", authorizedClient.getAccessToken().getExpiresAt());
    }

    return authorizedClient;
  }

  private void invalidateLoginAttempt(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    if (session != null) {
      session.invalidate();
    }
    throw new LogoutWithErrorCodeException(ErrorCode.FORBIDDEN_AMR);
  }

  private void validateIterableAmr(HttpServletRequest request, Iterable<?> amrIterable) {
    var noSupportedAmr = StreamSupport.stream(amrIterable.spliterator(), false)
            .filter(amrValue -> {
              if (!(amrValue instanceof String)) {
                return false;
              }
              return oAuthSecurityProperties.allowedAmr().contains(amrValue);
            })
            .findAny()
            .isEmpty();

    if (noSupportedAmr) {
      invalidateLoginAttempt(request);
    }
  }

  private void validateStringAmr(HttpServletRequest request, String amr) {
    if (!oAuthSecurityProperties.allowedAmr().contains(amr)) {
      invalidateLoginAttempt(request);
    }
  }
}
