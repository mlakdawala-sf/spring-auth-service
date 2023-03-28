package com.mudassir.authenticationservice.models;

import java.util.List;
import java.util.UUID;

import com.mudassir.authenticationservice.models.base.UserModifiableEntity;

import jakarta.persistence.*;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "roles", schema = "main")
public class Role extends UserModifiableEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  private String name;
  private int roleType;
  private List<String> permissions;
  private String allowedClients;
}
