package com.mudassir.authenticationservice.repositories;


import com.mudassir.authenticationservice.models.Role;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends CrudRepository<Role, UUID> {
    Optional<Role> findByName(String name);

    Role findByRoleType(int roleType);

}