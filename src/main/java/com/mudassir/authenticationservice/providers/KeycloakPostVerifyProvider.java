package com.mudassir.authenticationservice.providers;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.payload.keycloak.KeycloakUserDTO;

@Service
public class KeycloakPostVerifyProvider {

  public Optional<User> provide(KeycloakUserDTO keycloakUserDTO) {
    return null;
  }
}
