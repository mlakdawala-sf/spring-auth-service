package com.mudassir.authenticationservice.enums;

public enum UserStatus {
  REGISTERED(0),
  ACTIVE(1),
  INACTIVE(2),
  PASSWORD_CHANGE_NEEDED(3),
  REJECTED(4);

  public final int label;

  private UserStatus(int label) {
    this.label = label;
  }
}
