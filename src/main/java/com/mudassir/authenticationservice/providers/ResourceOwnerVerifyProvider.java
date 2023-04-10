package com.mudassir.authenticationservice.providers;

import com.mudassir.authenticationservice.enums.AuthErrorKeys;
import com.mudassir.authenticationservice.enums.AuthenticateErrorKeys;
import com.mudassir.authenticationservice.enums.UserStatus;
import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.models.UserTenant;
import com.mudassir.authenticationservice.payload.LoginDto;
import com.mudassir.authenticationservice.payload.UserVerificationDTO;
import com.mudassir.authenticationservice.repositories.AuthClientRepository;
import com.mudassir.authenticationservice.repositories.UserRepository;
import com.mudassir.authenticationservice.repositories.UserTenantRepository;
import com.mudassir.authenticationservice.services.AuthService;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;

@AllArgsConstructor
@Service
public class ResourceOwnerVerifyProvider {

  private UserRepository userRepository;
  private UserTenantRepository userTenantRepository;
  private AuthClientRepository authClientRepository;
  private AuthService authService;

  public UserVerificationDTO value(LoginDto loginDto) throws HttpServerErrorException {
    Optional<User> user;

    try {
      user =
        this.authService.verifyPassword(loginDto.getUsername(), loginDto.getPassword());
    } catch (Exception error) {
      // TODO
      // const otp: Otp = await this.otpRepository.get(username);
      // if (!otp || otp.otp !== password) {
      // throw new HttpErrors.Unauthorized(AuthErrorKeys.InvalidCredentials);
      // }
      user = this.userRepository.findUserByUsername(loginDto.getUsername());
      if (user.isEmpty()) {
        throw new HttpServerErrorException(
          HttpStatus.UNAUTHORIZED,
          AuthErrorKeys.InvalidCredentials.label
        );
      }
    }
    UserTenant userTenant =
      this.userTenantRepository.findUserBy(
          user.get().getId(),
          user.get().getDefaultTenantId(),
          Arrays.asList(UserStatus.REJECTED, UserStatus.INACTIVE)
        )
        .orElseThrow(() ->
          new HttpServerErrorException(
            HttpStatus.UNAUTHORIZED,
            AuthenticateErrorKeys.UserInactive.label
          )
        );

    AuthClient client =
      this.authClientRepository.findAuthClientByClientId(loginDto.getClient_id())
        .orElseThrow(() ->
          new HttpServerErrorException(
            HttpStatus.UNAUTHORIZED,
            AuthErrorKeys.ClientInvalid.label
          )
        );

    if (!user.get().getAuthClientIds().contains(client.getId())) {
      throw new HttpServerErrorException(
        HttpStatus.UNAUTHORIZED,
        AuthErrorKeys.ClientInvalid.label
      );
    } else if (!Objects.equals(client.getClientSecret(), loginDto.getClient_secret())) {
      throw new HttpServerErrorException(
        HttpStatus.UNAUTHORIZED,
        AuthErrorKeys.ClientVerificationFailed.label
      );
    }

    return new UserVerificationDTO(client, user.get());
  }
}
