package com.mudassir.authenticationservice.repositories;

import com.mudassir.authenticationservice.models.Role;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.repository.CrudRepository;

public interface RoleRepository extends CrudRepository<Role, UUID> {
  Optional<Role> findByName(String name);

  Optional<Role> findByRoleType(int roleType);
}
