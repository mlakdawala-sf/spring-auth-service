package com.mudassir.authenticationservice.exception;

import org.springframework.http.HttpStatus;

public class CommonRuntimeException extends RuntimeException {

  private HttpStatus status;
  private String message;

  public CommonRuntimeException(HttpStatus status, String message) {
    this.status = status;
    this.message = message;
  }

  public CommonRuntimeException(String message, HttpStatus status, String message1) {
    super(message);
    this.status = status;
    this.message = message1;
  }

  public HttpStatus getStatus() {
    return status;
  }

  @Override
  public String getMessage() {
    return message;
  }
}
