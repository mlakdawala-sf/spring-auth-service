package com.mudassir.authenticationservice.repositories;


import com.mudassir.authenticationservice.models.AuthClient;
import org.springframework.data.repository.CrudRepository;

public interface AuthClientRepository extends CrudRepository<AuthClient, String> {
    AuthClient findAuthClientByClientId(String clientId);
    AuthClient findAuthClientByClientIdAndClientSecret(String clientId,String clientSecret);
}
