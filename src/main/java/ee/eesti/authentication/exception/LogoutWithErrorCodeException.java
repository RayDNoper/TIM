package ee.eesti.authentication.exception;

import lombok.Getter;

@Getter
public class LogoutWithErrorCodeException extends RuntimeException {

  private final ErrorCode errorCode;

  public LogoutWithErrorCodeException(ErrorCode errorCode) {
    super("Logout error with code %s".formatted(errorCode));
    this.errorCode = errorCode;
  }
}
