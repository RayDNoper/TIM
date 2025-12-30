package ee.eesti.authentication.session;

import lombok.NoArgsConstructor;

import static lombok.AccessLevel.PRIVATE;

@NoArgsConstructor(access = PRIVATE)
public class SessionContext {

  public static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";
  public static final String SESSION_LOGIN_REDIRECT = SessionContext.class.getName() + ".SESSION_LOGIN_REDIRECT";
  public static final String CACHE_LOGOUT_REDIRECT = "logout:sessions:redirect_uri:";
  public static final String SESSION_USER_AGENT = SessionContext.class.getName() + ".SESSION_USER_AGENT";
}
