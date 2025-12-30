package ee.eesti.authentication.service;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SessionUtil {
  public static String getHashCodeFromSessionId(String sessionId) {
    try {
      var sha256Digest = MessageDigest.getInstance("SHA-256");
      var sessionHashBytes = sha256Digest.digest(sessionId.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(sessionHashBytes);
    } catch (Exception e) {
      log.error("Failed to generate hash code");
    }
    return String.valueOf(sessionId.hashCode());
  }
}
