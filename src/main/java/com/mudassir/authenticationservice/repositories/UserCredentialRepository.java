package com.mudassir.authenticationservice.repositories;


import com.mudassir.authenticationservice.models.UserCredential;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserCredentialRepository extends CrudRepository<UserCredential, String> {
    Optional<UserCredential> findByUserId(UUID userId);
}