package com.mudassir.authenticationservice.repositories;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.mudassir.authenticationservice.models.Tenant;

public interface TenantRepository extends CrudRepository<Tenant, String> {
  Optional<Tenant> findByKey(String key);
}
