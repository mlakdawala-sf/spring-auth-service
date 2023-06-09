package com.mudassir.authenticationservice.payload;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class JWTAuthResponse {

  private String accessToken;
  private String refreshToken;
  private long expires;
  private String tokenType = "Bearer";
}
