package com.mudassir.authenticationservice.payload;

import com.mudassir.authenticationservice.enums.AuthProvider;
import com.mudassir.authenticationservice.models.User;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RegisterDto {

  private User user;
  private UUID defaultTenantId;
  private UUID roleId;
  private String authId;
  private AuthProvider authProvider;
}
