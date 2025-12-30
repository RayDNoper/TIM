package ee.eesti.authentication.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Component
public class RedisOidcSessionRegistry implements OidcSessionRegistry {

  private static final String REDIS_SESSION_PREFIX = "oidc:sessions:";

  @Value("${app.oidc-session-timeout-minutes:720}")
  private int oidcSessionTimeoutMinutes;

  private final ValueOperations<String, OidcSessionInformation> valueOperations;
  private final RedisTemplate<String, OidcSessionInformation> redisTemplate;

  public RedisOidcSessionRegistry(RedisTemplate<String, OidcSessionInformation> redisTemplate) {
    this.redisTemplate = redisTemplate;
    this.valueOperations = redisTemplate.opsForValue();
  }

  @Override
  public void saveSessionInformation(OidcSessionInformation info) {
    var ssoSessionId = info.getPrincipal().getClaimAsString("sid");
    String key = getRedisKey(ssoSessionId);
    valueOperations.set(key, info, Duration.ofMinutes(oidcSessionTimeoutMinutes));
  }

  @Override
  public OidcSessionInformation removeSessionInformation(String clientSessionId) {
    String key = getRedisKey(clientSessionId);
    OidcSessionInformation value = valueOperations.get(key);
    if (value != null) {
      redisTemplate.delete(key);
    }
    return value;
  }

  @Override
  public Iterable<OidcSessionInformation> removeSessionInformation(OidcLogoutToken logoutToken) {
    String key = getRedisKey(logoutToken.getSessionId());
    OidcSessionInformation value = valueOperations.get(key);
    if (value != null) {
      redisTemplate.delete(key);
      return List.of(value);
    }
    return List.of();
  }

  private String getRedisKey(String sessionId) {
    return REDIS_SESSION_PREFIX + sessionId;
  }
}