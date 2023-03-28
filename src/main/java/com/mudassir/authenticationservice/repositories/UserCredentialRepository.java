package com.mudassir.authenticationservice.repositories;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.repository.CrudRepository;

import com.mudassir.authenticationservice.models.UserCredential;

public interface UserCredentialRepository extends CrudRepository<UserCredential, String> {
  Optional<UserCredential> findByUserId(UUID userId);
}
