package com.mudassir.authenticationservice.repositories;

import java.util.ArrayList;
import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.mudassir.authenticationservice.models.AuthClient;

public interface AuthClientRepository extends CrudRepository<AuthClient, String> {
  AuthClient findAuthClientByClientId(String clientId);

  AuthClient findAuthClientByClientIdAndClientSecret(
      String clientId,
      String clientSecret);

  @Query("SELECT a from AuthClient a where a.id IN :allowedClients ")
  ArrayList<AuthClient> findByAllowedClients(List<String> allowedClients);
}
