package ee.eesti.authentication.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Data
@Component
@ConfigurationProperties(prefix = "app")
public class OAuthGatewayProperties {

  private boolean oauthEnabled;
  private Proxy proxy;
  private Uri uri;
  private RedirectUri redirectUri;
  private String sessionCookieName;
  private Boolean returnUnauthorizedOnTimeout;

  @Data
  public static class Proxy {
    private Map<String, Sso> sso;
    private String targetBaseUri;
    private String backChannelLogoutUri;
  }

  @Data
  public static class Sso {
    private String uri;
    private String logoutUri;
  }

  @Data
  public static class Uri {
    private String ingress;
    private String loginRedirectFallback;
    private String logoutRedirectFallback;
  }

  @Data
  public static class RedirectUri {
    private List<String> whitelist;
  }
}
