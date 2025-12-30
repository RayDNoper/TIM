package ee.eesti.authentication.security;

import ee.eesti.authentication.configuration.OAuthGatewayProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

  private final OAuthGatewayProperties oAuthGatewayProperties;

  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                      AuthenticationException exception) throws IOException, ServletException {
    log.error("Failure during login: {}", exception.getMessage(), exception);
    // TODO Do we want to give a message for user?
    response.sendRedirect(oAuthGatewayProperties.getUri().getLogoutRedirectFallback());
  }
}