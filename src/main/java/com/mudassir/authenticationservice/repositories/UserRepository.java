package com.mudassir.authenticationservice.repositories;


import com.mudassir.authenticationservice.models.User;
import org.springframework.data.repository.CrudRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends CrudRepository<User, UUID> {

    List<User> findByLastName(String lastName);

    Optional<User> findByEmail(String email);

    Optional<User> findUserByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

}