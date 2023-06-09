package com.mudassir.authenticationservice.payload;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class LoginDto {

  private String username;
  private String password;
  private String client_id;
  private String client_secret;
}
