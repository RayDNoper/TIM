package ee.eesti.authentication.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Data
@Component
@ConfigurationProperties(prefix = "app.authentication-request")
public class AuthenticationRequestProperties {
  private List<String> propagatedQueryParams;
  private Map<String, String> defaultQueryParams;
}
