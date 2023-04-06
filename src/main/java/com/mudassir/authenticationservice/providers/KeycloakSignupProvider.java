package com.mudassir.authenticationservice.providers;

import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;

import com.mudassir.authenticationservice.enums.AuthErrorKeys;
import com.mudassir.authenticationservice.enums.AuthProvider;
import com.mudassir.authenticationservice.enums.RoleKey;
import com.mudassir.authenticationservice.models.Role;
import com.mudassir.authenticationservice.models.Tenant;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.payload.RegisterDto;
import com.mudassir.authenticationservice.payload.keycloak.KeycloakUserDTO;
import com.mudassir.authenticationservice.repositories.RoleRepository;
import com.mudassir.authenticationservice.repositories.TenantRepository;
import com.mudassir.authenticationservice.service.impl.AuthService;

import lombok.AllArgsConstructor;

@AllArgsConstructor
@Service
public class KeycloakSignupProvider {

  private final TenantRepository tenantRepository;
  private final AuthService authService;
  private final RoleRepository roleRepository;

  public Optional<User> provide(KeycloakUserDTO keycloakUserDTO) {
    //           const allowedDomains = process.env.AUTO_SIGNUP_DOMAINS ?? '*';
    //        if (allowedDomains !== '*') {
    //        const allowedDomainList = allowedDomains.split(',');
    //        const profileDomain = profile.email.split('@')[1];
    //            if (!allowedDomainList.includes(profileDomain)) {
    //                this.logger.error('Email domain not allowed for auto sign up !');
    //                throw new HttpErrors.Unauthorized(AuthErrorKeys.InvalidCredentials);
    //            }
    //        }
    //
    //      const defaultRole =
    //                await this.userOpsService.findRoleToAssignForKeycloakUser(profile);
    Optional<Tenant> tenant = this.tenantRepository.findByKey("master");
    Optional<Role> defaultRole =
      this.roleRepository.findByRoleType(RoleKey.Default.label);
    if (tenant.isEmpty()) {
      throw new HttpServerErrorException(
        HttpStatus.UNAUTHORIZED,
        AuthErrorKeys.InvalidCredentials.label
      );
    }

    if (defaultRole.isEmpty()) {
      throw new HttpServerErrorException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "Role not found"
      );
    }
    User userToCreate = new User();
    userToCreate.setUsername(keycloakUserDTO.getPreferred_username());
    userToCreate.setFirstName(keycloakUserDTO.getGiven_name());
    userToCreate.setLastName(keycloakUserDTO.getFamily_name());

    RegisterDto registerDto = new RegisterDto();
    registerDto.setAuthProvider(AuthProvider.KEYCLOAK);
    registerDto.setDefaultTenantId(tenant.get().getId());
    registerDto.setUser(userToCreate);
    registerDto.setAuthId(keycloakUserDTO.getSub());
    registerDto.setRoleId(defaultRole.get().getId());

    return Optional.ofNullable(this.authService.register(registerDto));
  }
}
