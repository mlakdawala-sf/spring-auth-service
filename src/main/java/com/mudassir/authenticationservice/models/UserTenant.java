package com.mudassir.authenticationservice.models;

import com.mudassir.authenticationservice.enums.UserStatus;
import com.mudassir.authenticationservice.models.base.UserModifiableEntity;
import jakarta.persistence.*;
import java.util.UUID;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "user_tenants", schema = "main")
public class UserTenant extends UserModifiableEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  private String locale;
  private UserStatus status;
  private UUID userId;
  private UUID tenantId;
  private UUID roleId;
}
