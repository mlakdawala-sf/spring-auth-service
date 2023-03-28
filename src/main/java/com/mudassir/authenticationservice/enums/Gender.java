package com.mudassir.authenticationservice.enums;

public enum Gender {
  Male("M"),
  Female("F"),
  Other("O"),
  Unknown("U");

  public final String label;

  private Gender(String label) {
    this.label = label;
  }
}
