package com.mudassir.authenticationservice.repositories;

import org.springframework.data.repository.CrudRepository;

import com.mudassir.authenticationservice.models.AuthClient;

public interface AuthClientRepository extends CrudRepository<AuthClient, String> {
  AuthClient findAuthClientByClientId(String clientId);
  AuthClient findAuthClientByClientIdAndClientSecret(
    String clientId,
    String clientSecret
  );
}
