package com.mudassir.authenticationservice.repositories;

import com.mudassir.authenticationservice.models.UserCredential;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.repository.CrudRepository;

public interface UserCredentialRepository extends CrudRepository<UserCredential, String> {
  Optional<UserCredential> findByUserId(UUID userId);

  Optional<UserCredential> findByAuthIdAndAuthProvider(
    String authId,
    String authProvider
  );
}
