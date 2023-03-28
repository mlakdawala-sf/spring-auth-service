package com.mudassir.authenticationservice.models;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import com.mudassir.authenticationservice.enums.Gender;
import com.mudassir.authenticationservice.models.base.UserModifiableEntity;

import jakarta.persistence.*;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@EqualsAndHashCode(callSuper = true)
@Table(name = "users", schema = "main")
public class User extends UserModifiableEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  private String firstName;
  private String lastName;
  private String middleName;
  private String username;
  private String email;
  private String designation;
  private String phone;
  private String lastLogin;
  private Gender gender;
  private Date dob;
  private UUID defaultTenantId;
  private List<Integer> authClientIds;
}
