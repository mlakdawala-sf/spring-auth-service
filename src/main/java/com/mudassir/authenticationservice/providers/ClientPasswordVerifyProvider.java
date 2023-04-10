package com.mudassir.authenticationservice.providers;

import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.repositories.AuthClientRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Service
public class ClientPasswordVerifyProvider {

  private final AuthClientRepository authClientRepository;

  public AuthClient value(String clientId, String clientSecret) {
    return this.authClientRepository.findAuthClientByClientIdAndClientSecret(
        clientId,
        clientSecret
      );
  }
}
