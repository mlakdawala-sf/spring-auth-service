package com.mudassir.authenticationservice.repositories;


import com.mudassir.authenticationservice.enums.UserStatus;
import com.mudassir.authenticationservice.models.UserTenant;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface UserTenantRepository extends CrudRepository<UserTenant, String> {
    UserTenant findUserTenantByUserId(UUID userId);
    @Query("SELECT ut from UserTenant ut where userId=:userId AND tenantId=:tenantId AND status NOT IN :statuses" )
    UserTenant findUserBy(UUID userId,UUID tenantId,@Param("statuses") List<UserStatus> statuses);

}