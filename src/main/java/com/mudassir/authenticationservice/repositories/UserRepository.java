package com.mudassir.authenticationservice.repositories;

import com.mudassir.authenticationservice.models.User;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, UUID> {
  List<User> findByLastName(String lastName);

  Optional<User> findByEmail(String email);

  Optional<User> findUserByUsername(String username);

  @Query(
    value = "SELECT u FROM User u WHERE u.username=:usernameOrEmail OR u.email=:usernameOrEmail"
  )
  Optional<User> findFirstUserByUsernameOrEmail(String usernameOrEmail);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);
}
