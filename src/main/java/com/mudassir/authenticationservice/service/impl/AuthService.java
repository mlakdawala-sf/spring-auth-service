package com.mudassir.authenticationservice.service.impl;

import java.util.ArrayList;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;

import com.mudassir.authenticationservice.enums.AuthErrorKeys;
import com.mudassir.authenticationservice.enums.AuthProvider;
import com.mudassir.authenticationservice.enums.AuthenticateErrorKeys;
import com.mudassir.authenticationservice.enums.RoleKey;
import com.mudassir.authenticationservice.enums.UserStatus;
import com.mudassir.authenticationservice.exception.CommonRuntimeException;
import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.models.JwtTokenRedis;
import com.mudassir.authenticationservice.models.Role;
import com.mudassir.authenticationservice.models.Tenant;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.models.UserCredential;
import com.mudassir.authenticationservice.models.UserTenant;
import com.mudassir.authenticationservice.payload.AuthTokenRequest;
import com.mudassir.authenticationservice.payload.JWTAuthResponse;
import com.mudassir.authenticationservice.payload.LoginDto;
import com.mudassir.authenticationservice.payload.RegisterDto;
import com.mudassir.authenticationservice.providers.AuthCodeGeneratorProvider;
import com.mudassir.authenticationservice.repositories.AuthClientRepository;
import com.mudassir.authenticationservice.repositories.JwtTokenRedisRepository;
import com.mudassir.authenticationservice.repositories.RoleRepository;
import com.mudassir.authenticationservice.repositories.TenantRepository;
import com.mudassir.authenticationservice.repositories.UserCredentialRepository;
import com.mudassir.authenticationservice.repositories.UserRepository;
import com.mudassir.authenticationservice.repositories.UserTenantRepository;

import lombok.AllArgsConstructor;

@AllArgsConstructor
@Service
public class AuthService {

  private final UserRepository userRepository;
  private final RoleRepository roleRepository;
  private final TenantRepository tenantRepository;
  private final AuthClientRepository authClientRepository;
  private final PasswordEncoder passwordEncoder;
  private final UserCredentialRepository userCredentialRepository;
  private final UserTenantRepository userTenantRepository;
  private final LoginHelperService loginHelperService;
  private final AuthCodeGeneratorProvider authCodeGeneratorProvider;
  private final JwtTokenRedisRepository jwtTokenRedisRepository;

  public JWTAuthResponse getTokenByCode(AuthTokenRequest authTokenRequest) {
    this.authClientRepository.findAuthClientByClientId(authTokenRequest.getClientId())
        .orElseThrow(() -> new CommonRuntimeException(
            HttpStatus.UNAUTHORIZED,
            AuthErrorKeys.ClientInvalid.label));
    JwtTokenRedis jwtTokenObject = this.jwtTokenRedisRepository.findById(authTokenRequest.getCode())
        .orElseThrow(() -> new CommonRuntimeException(
            HttpStatus.UNAUTHORIZED,
            AuthenticateErrorKeys.TokenRevoked.label));
    JWTAuthResponse jwtAuthResponse = new JWTAuthResponse();
    jwtAuthResponse.setAccessToken(jwtTokenObject.getToken());
    jwtAuthResponse.setTokenType("Bearer");
    // jwtAuthResponse.setExpiresIn(jwtTokenObject.getExpiresIn());
    // jwtAuthResponse.setRefreshToken(jwtTokenObject.getRefreshToken());
    return jwtAuthResponse;
  }

  public String login(LoginDto loginDto, AuthClient authClient, User authUser) {
    this.loginHelperService.verifyClientUserLogin(loginDto, authClient, authUser);
    String token = this.authCodeGeneratorProvider.provide(authUser);

    return token;
  }

  public User register(RegisterDto registerDto) {
    // add check for username exists in database
    if (userRepository.existsByUsername(registerDto.getUser().getUsername())) {
      throw new CommonRuntimeException(
          HttpStatus.BAD_REQUEST,
          "Username is already exists!.");
    }
    Optional<User> userExists = userRepository.findByEmail(registerDto.getAuthId());
    // add check for email exists in database
    if (userExists.isPresent()) {
      throw new CommonRuntimeException(
          HttpStatus.BAD_REQUEST,
          "Email is already exists!.");
    }
    Optional<Role> defaultRole = roleRepository.findByRoleType(RoleKey.Default.label);
    Optional<Tenant> tenant = tenantRepository.findByKey("master");
    if (tenant.isEmpty()) {
      throw new HttpServerErrorException(
          HttpStatus.UNAUTHORIZED,
          AuthErrorKeys.InvalidCredentials.label);
    }

    if (defaultRole.isEmpty()) {
      throw new HttpServerErrorException(
          HttpStatus.INTERNAL_SERVER_ERROR,
          "Role not found");
    }

    Optional<UserCredential> userCreds = this.userCredentialRepository.findByAuthIdAndAuthProvider(
        registerDto.getAuthId(),
        registerDto.getAuthProvider().label);
    if (userCreds.isPresent()) {
      throw new CommonRuntimeException(HttpStatus.BAD_REQUEST, "User already exists!.");
    }
    Optional<User> user = this.userRepository.findFirstUserByUsernameOrEmail(
        registerDto.getUser().getUsername().toLowerCase());
    if (user.isPresent()) {
      Optional<UserTenant> userTenant = this.userTenantRepository.findUserBy(user.get().getId(), tenant.get().getId());
      if (userTenant.isPresent()) {
        throw new CommonRuntimeException(
            HttpStatus.BAD_REQUEST,
            "User already exists and belongs to this tenant");
      } else {
        this.createUserTenantData(
            registerDto.getUser(),
            UserStatus.ACTIVE,
            user.get().getId(),
            defaultRole.get().getId(),
            tenant.get().getId());
        return user.get();
      }
    }
    ArrayList<AuthClient> authClients = this.authClientRepository.findByAllowedClients(
        defaultRole.get().getAllowedClients());
    registerDto
        .getUser()
        .setAuthClientIds(
            authClients
                .stream()
                .map(AuthClient::getId)
                .collect(java.util.stream.Collectors.toList()));

    registerDto.getUser().setDefaultTenantId(tenant.get().getId());
    User savedUser = this.createUser(
        registerDto.getUser(),
        registerDto.getAuthProvider(),
        registerDto.getAuthId());
    this.createUserTenantData(
        savedUser,
        UserStatus.ACTIVE,
        savedUser.getId(),
        defaultRole.get().getId(),
        tenant.get().getId());
    return savedUser;
  }

  User createUser(User user, AuthProvider provider, String authId) {
    try {
      Optional<User> userExists = this.userRepository.findUserByUsername(user.getUsername());
      if (userExists.isPresent()) {
        throw new CommonRuntimeException(HttpStatus.BAD_REQUEST, "User already exists!.");
      }

      user = this.userRepository.save(user);
      UserCredential userCredential = new UserCredential();
      userCredential.setUserId(user.getId());
      switch (provider) {
        case KEYCLOAK:
          userCredential.setAuthId(authId);
          userCredential.setAuthProvider(AuthProvider.KEYCLOAK.label);
          break;
        // case INTERNAL:
        // userCredential.setAuthProvider(AuthProvider.INTERNAL.label);
        // userCredential.setPassword(passwordEncoder.encode(defaultPassword));
        // break;

        default:
          String defaultPassword = "ss";
          userCredential.setAuthProvider(AuthProvider.INTERNAL.label);
          userCredential.setPassword(passwordEncoder.encode(defaultPassword));
          break;
      }
      this.userCredentialRepository.save(userCredential);
    } catch (Exception e) {
      throw new CommonRuntimeException(
          HttpStatus.INTERNAL_SERVER_ERROR,
          "Error while creating user");
    }
    return user;
  }

  UserTenant createUserTenantData(
      User user,
      UserStatus status,
      UUID userId,
      UUID roleId,
      UUID tenantId) {
    // User savedUser = userRepository.save(user);
    UserTenant userTenant = new UserTenant();
    userTenant.setRoleId(roleId);
    userTenant.setStatus(status);
    userTenant.setTenantId(tenantId);
    userTenant.setUserId(user.getId());
    userTenantRepository.save(userTenant);
    return userTenant;
  }

  public Optional<User> verifyPassword(String username, String password) {
    Optional<User> user = this.userRepository.findUserByUsername(username.toLowerCase());
    if (user.isEmpty() || user.get().getDeleted()) {
      throw new HttpServerErrorException(
          HttpStatus.UNAUTHORIZED,
          AuthenticateErrorKeys.UserDoesNotExist.label);
    }
    Optional<UserCredential> creds = this.userCredentialRepository.findByUserId(user.get().getId());
    if (creds.isPresent() &&
        creds.get().getPassword().isEmpty() ||
        !Objects.equals(creds.get().getAuthProvider(), AuthProvider.INTERNAL.label) ||
        !(BCrypt.checkpw(password, creds.get().getPassword()))) {
      // this.logger.error('User creds not found in DB or is invalid');
      throw new HttpServerErrorException(
          HttpStatus.UNAUTHORIZED,
          AuthErrorKeys.InvalidCredentials.label);
    } else {
      return user;
    }
  }
}
