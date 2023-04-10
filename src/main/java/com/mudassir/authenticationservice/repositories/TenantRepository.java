package com.mudassir.authenticationservice.repositories;

import com.mudassir.authenticationservice.models.Tenant;
import java.util.Optional;
import org.springframework.data.repository.CrudRepository;

public interface TenantRepository extends CrudRepository<Tenant, String> {
  Optional<Tenant> findByKey(String key);
}
