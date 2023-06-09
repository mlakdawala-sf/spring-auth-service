package com.mudassir.authenticationservice.repositories;

import com.mudassir.authenticationservice.models.AuthClient;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

public interface AuthClientRepository extends CrudRepository<AuthClient, String> {
  Optional<AuthClient> findAuthClientByClientId(String clientId);

  AuthClient findAuthClientByClientIdAndClientSecret(
    String clientId,
    String clientSecret
  );

  @Query("SELECT a from AuthClient a where a.clientId IN :allowedClients ")
  ArrayList<AuthClient> findByAllowedClients(List<String> allowedClients);
}
