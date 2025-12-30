package ee.eesti.authentication.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

@Data
@ConfigurationProperties(prefix = "sso-resolver")
public class SsoResolverProperties {

  private Map<String, Attributes> sso;
  private String defaultSso;

  @Data
  public static class Attributes {
    private String headerName;
    private String headerValue;
  }
}
