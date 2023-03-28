package com.mudassir.authenticationservice.repositories;


import com.mudassir.authenticationservice.models.Tenant;
import org.springframework.data.repository.CrudRepository;

public interface TenantRepository extends CrudRepository<Tenant, String> {
    Tenant findByKey(String key);
}