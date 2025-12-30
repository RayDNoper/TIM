package ee.eesti.authentication.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@ConfigurationProperties(prefix = "app.security")
public record OAuthSecurityProperties(
    UserAgent userAgent,
    boolean removeUnknownAuthorizationHeader,
    List<String> allowedAmr,
    List<String> allowedAuthorizationHeaderIssuers
) {

  public record UserAgent(
      boolean enabled
  ) {}
}
