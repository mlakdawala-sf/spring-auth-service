package com.mudassir.authenticationservice.models;

import com.mudassir.authenticationservice.models.base.UserModifiableEntity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "auth_clients", schema = "main")
public class AuthClient extends UserModifiableEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private String id;

  private String clientId;
  private String clientSecret;
  private String redirectUrl;
  private String secret;
  private long accessTokenExpiration;
  private long refreshTokenExpiration;
  private long authCodeExpiration;
}
