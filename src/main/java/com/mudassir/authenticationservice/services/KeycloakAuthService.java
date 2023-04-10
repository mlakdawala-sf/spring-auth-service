package com.mudassir.authenticationservice.services;

import com.mudassir.authenticationservice.enums.AuthErrorKeys;
import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.models.UserCredential;
import com.mudassir.authenticationservice.payload.keycloak.KeycloakAuthResponse;
import com.mudassir.authenticationservice.payload.keycloak.KeycloakUserDTO;
import com.mudassir.authenticationservice.providers.*;
import com.mudassir.authenticationservice.repositories.AuthClientRepository;
import com.mudassir.authenticationservice.repositories.UserCredentialRepository;
import com.mudassir.authenticationservice.repositories.UserRepository;
import com.mudassir.authenticationservice.repositories.UserTenantRepository;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;

@AllArgsConstructor
@Service
public class KeycloakAuthService {

  private final UserRepository userRepository;
  private final UserCredentialRepository userCredentialRepository;

  private final KeycloakFacadeService keycloakFacadeService;
  private final KeycloakPreVerifyProvider keycloakPreVerifyProvider;
  private final KeycloakPostVerifyProvider keycloakPostVerifyProvider;
  private final KeycloakSignupProvider keycloakSignupProvider;
  private final AuthCodeGeneratorProvider authCodeGeneratorProvider;

  public String login(String code) {
    KeycloakAuthResponse keycloakAuthResponse =
      this.keycloakFacadeService.keycloakAuthByCode(code);
    KeycloakUserDTO keycloakUserDTO =
      this.keycloakFacadeService.getKeycloakUserProfile(
          keycloakAuthResponse.getAccess_token()
        );
    String usernameOrEmail = keycloakUserDTO.getEmail();
    Optional<User> user =
      this.userRepository.findFirstUserByUsernameOrEmail(usernameOrEmail);

    user = this.keycloakPreVerifyProvider.provide(user, keycloakUserDTO);
    if (user.isEmpty()) {
      user = this.keycloakSignupProvider.provide(keycloakUserDTO);
      if (user.isEmpty()) {
        throw new HttpServerErrorException(
          HttpStatus.UNAUTHORIZED,
          AuthErrorKeys.UserVerificationFailed.label
        );
      }
    }
    Optional<UserCredential> userCredential =
      this.userCredentialRepository.findByUserId(user.get().getId());
    if (
      userCredential.isEmpty() ||
      !userCredential.get().getAuthProvider().equals("keycloak") ||
      (
        // userCredential.get().getAuthId() != keycloakUserDTO.getSub() &&
        !userCredential.get().getAuthId().equals(keycloakUserDTO.getPreferred_username())
      )
    ) {
      throw new HttpServerErrorException(
        HttpStatus.UNAUTHORIZED,
        AuthErrorKeys.UserVerificationFailed.label
      );
    }

    // TODO
    // this.keycloakPostVerifyProvider.provide()

    return authCodeGeneratorProvider.provide(user.get());
  }
}
