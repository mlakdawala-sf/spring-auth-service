package com.mudassir.authenticationservice.service.impl;

import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpServerErrorException;

import com.mudassir.authenticationservice.enums.AuthErrorKeys;
import com.mudassir.authenticationservice.enums.UserStatus;
import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.models.UserTenant;
import com.mudassir.authenticationservice.payload.LoginDto;
import com.mudassir.authenticationservice.repositories.UserTenantRepository;

@Service
public class LoginHelperService {

  private UserTenantRepository userTenantRepository;

  public LoginHelperService(UserTenantRepository userTenantRepository) {
    this.userTenantRepository = userTenantRepository;
  }

  public UserStatus verifyClientUserLogin(LoginDto req, AuthClient client, User user) {
    User currentUser = user;

    // if (client) {
    // this.logger.error('Auth client not found or invalid');
    // throw new HttpErrors.Unauthorized(AuthErrorKeys.ClientInvalid);
    // }
    // if (!currentUser) {
    // this.logger.error('Auth user not found or invalid');
    // throw new HttpErrors.Unauthorized(AuthErrorKeys.InvalidCredentials);
    // }
    Optional<UserTenant> userTenant = userTenantRepository.findUserTenantByUserId(
      currentUser.getId()
    );
    UserStatus userStatus = userTenant.get().getStatus();

    if (currentUser.getAuthClientIds().size() == 0) {
      // this.logger.error('No allowed auth clients found for this user in DB');

      throw new HttpServerErrorException(
        HttpStatus.UNPROCESSABLE_ENTITY,
        AuthErrorKeys.ClientUserMissing.label
      );
    } else if (!StringUtils.hasLength(req.getClient_secret())) {
      // this.logger.error('client secret key missing from request object');
      throw new HttpServerErrorException(
        HttpStatus.BAD_REQUEST,
        AuthErrorKeys.ClientSecretMissing.label
      );
      // sonarignore:start
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } else if (!currentUser.getAuthClientIds().contains(client.getId())) {
      // sonarignore:end
      // this.logger.error(
      // 'User is not allowed to access client id passed in request',
      // );
      throw new HttpServerErrorException(
        HttpStatus.UNAUTHORIZED,
        AuthErrorKeys.ClientInvalid.label
      );
    } else if (userStatus == UserStatus.REGISTERED) {
      // this.logger.error('User is in registered state');
      throw new HttpServerErrorException(HttpStatus.BAD_REQUEST, "User not active yet");
    }
    return userStatus;
  }
}
