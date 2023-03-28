package com.mudassir.authenticationservice.enums;

public enum TenantStatus {
  ACTIVE(1),
  INACTIVE(0);

  public final int label;

  private TenantStatus(int label) {
    this.label = label;
  }
}
