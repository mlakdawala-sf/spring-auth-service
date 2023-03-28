package com.mudassir.authenticationservice.repositories;

import org.springframework.data.repository.CrudRepository;

import com.mudassir.authenticationservice.models.Tenant;

public interface TenantRepository extends CrudRepository<Tenant, String> {
  Tenant findByKey(String key);
}
