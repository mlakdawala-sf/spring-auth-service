package com.mudassir.authenticationservice.providers;

import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;

import com.mudassir.authenticationservice.enums.AuthErrorKeys;
import com.mudassir.authenticationservice.enums.UserStatus;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.models.UserTenant;
import com.mudassir.authenticationservice.payload.keycloak.KeycloakUserDTO;
import com.mudassir.authenticationservice.repositories.UserCredentialRepository;
import com.mudassir.authenticationservice.repositories.UserRepository;
import com.mudassir.authenticationservice.repositories.UserTenantRepository;

import lombok.AllArgsConstructor;

@AllArgsConstructor
@Service
public class KeycloakPreVerifyProvider {

  private final UserRepository userRepository;
  private final UserTenantRepository userTenantRepository;
  private final UserCredentialRepository userCredentialRepository;

  public Optional<User> provide(
    Optional<User> optionalUser,
    KeycloakUserDTO keycloakUserDTO
  ) {
    if (optionalUser.isEmpty()) {
      return optionalUser;
    }
    User user = optionalUser.get();
    if (
      user.getFirstName() != keycloakUserDTO.getGiven_name() ||
      user.getLastName() != keycloakUserDTO.getFamily_name() ||
      user.getUsername() != keycloakUserDTO.getPreferred_username()
    ) {
      user.setUsername(keycloakUserDTO.getPreferred_username());
      user.setFirstName(keycloakUserDTO.getGiven_name());
      user.setLastName(keycloakUserDTO.getFamily_name());
      this.userRepository.save(user);
    }
    Optional<UserTenant> userTenant =
      this.userTenantRepository.findUserTenantByUserId(user.getId());
    if (userTenant.isEmpty()) {
      throw new HttpServerErrorException(
        HttpStatus.UNAUTHORIZED,
        AuthErrorKeys.InvalidCredentials.label
      );
    }
    // role assignment pending to be updated
    if (userTenant.get().getStatus() == UserStatus.REGISTERED) {
      userTenant.get().setStatus(UserStatus.ACTIVE);
      this.userTenantRepository.save(userTenant.get());
      // await this.userCredsRepo.updateAll(
      // {
      // authId: profile.username,
      // authProvider: 'keycloak',
      // },
      // {
      // and: [
      // {userId: user.id as string},
      // {or: [{authProvider: 'keycloak'}, {authProvider: 'internal'}]},
      // ],
      // },
      // );
    }
    return Optional.of(user);
  }
}
