package com.mudassir.authenticationservice.models;

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
@Table(name = "user_credentials", schema = "main")
public class UserCredential extends UserModifiableEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  private String authProvider;
  private String authId;
  private String authToken;
  private String password;
  private UUID userId;
}
