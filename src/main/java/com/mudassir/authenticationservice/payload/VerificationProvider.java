package com.mudassir.authenticationservice.payload;

import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.models.User;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class VerificationProvider {

  private AuthClient authClient;
  private User authUser;
}
