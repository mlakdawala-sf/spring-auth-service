package com.mudassir.authenticationservice.repositories;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import com.mudassir.authenticationservice.enums.UserStatus;
import com.mudassir.authenticationservice.models.UserTenant;

public interface UserTenantRepository extends CrudRepository<UserTenant, String> {
  Optional<UserTenant> findUserTenantByUserId(UUID userId);

  @Query(
    "SELECT ut from UserTenant ut where userId=:userId AND tenantId=:tenantId AND status NOT IN :statuses"
  )
  UserTenant findUserBy(
    UUID userId,
    UUID tenantId,
    @Param("statuses") List<UserStatus> statuses
  );

  @Query("SELECT ut from UserTenant ut where userId=:userId AND tenantId=:tenantId")
  Optional<UserTenant> findUserBy(UUID userId, UUID tenantId);
}
