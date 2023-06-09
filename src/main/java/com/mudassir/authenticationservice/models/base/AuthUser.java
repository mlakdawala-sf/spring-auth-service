package com.mudassir.authenticationservice.models.base;

import com.mudassir.authenticationservice.enums.UserStatus;
import com.mudassir.authenticationservice.models.User;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class AuthUser
  extends User
  implements
    com.mudassir.authenticationservice.models.base.AuthUserWithPermissions<UUID, UUID, UUID> {

  UUID id;
  String username;
  String password;
  UUID identifier;
  List<String> permissions;
  int authClientId;
  String email;
  String role;
  String firstName;
  String lastName;
  String middleName;
  UUID tenantId;
  UUID userTenantId;
  Date passwordExpiryTime;
  List<String> allowedResources;
  String externalAuthToken;
  int age;
  String externalRefreshToken;
  UserStatus status;
  //    IUserPref userPreferences;
  //    DeviceInfo deviceInfo;
}
