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
import com.mudassir.authenticationservice.models.Role;
import com.mudassir.authenticationservice.models.Tenant;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.models.UserCredential;
import com.mudassir.authenticationservice.models.UserTenant;
import com.mudassir.authenticationservice.payload.LoginDto;
import com.mudassir.authenticationservice.payload.RegisterDto;
import com.mudassir.authenticationservice.repositories.AuthClientRepository;
import com.mudassir.authenticationservice.repositories.RoleRepository;
import com.mudassir.authenticationservice.repositories.TenantRepository;
import com.mudassir.authenticationservice.repositories.UserCredentialRepository;
import com.mudassir.authenticationservice.repositories.UserRepository;
import com.mudassir.authenticationservice.repositories.UserTenantRepository;
import com.mudassir.authenticationservice.security.JwtTokenProvider;

@Service
public class AuthService {

  private AuthenticationManager authenticationManager;
  private UserRepository userRepository;
  private RoleRepository roleRepository;
  private TenantRepository tenantRepository;
  private AuthClientRepository authClientRepository;
  private PasswordEncoder passwordEncoder;
  private JwtTokenProvider jwtTokenProvider;

  private UserCredentialRepository userCredentialRepository;
  private UserTenantRepository userTenantRepository;
  private LoginHelperService loginHelperService;

  public AuthService(
      AuthenticationManager authenticationManager,
      UserRepository userRepository,
      RoleRepository roleRepository,
      PasswordEncoder passwordEncoder,
      JwtTokenProvider jwtTokenProvider,
      UserCredentialRepository userCredentialRepository,
      TenantRepository tenantRepository,
      UserTenantRepository userTenantRepository,
      LoginHelperService loginHelperService) {
    this.authenticationManager = authenticationManager;
    this.userRepository = userRepository;
    this.roleRepository = roleRepository;
    this.passwordEncoder = passwordEncoder;
    this.jwtTokenProvider = jwtTokenProvider;
    this.userCredentialRepository = userCredentialRepository;
    this.tenantRepository = tenantRepository;
    this.userTenantRepository = userTenantRepository;
    this.loginHelperService = loginHelperService;
  }

  public String login(LoginDto loginDto, AuthClient authClient, User authUser) {
    this.loginHelperService.verifyClientUserLogin(loginDto, authClient, authUser);
    String token = jwtTokenProvider.generateToken(authUser);

    return token;
  }

  public User register(RegisterDto registerDto) {
    // add check for username exists in database
    if (userRepository.existsByUsername(registerDto.getUser().getUsername())) {
      throw new CommonRuntimeException(
          HttpStatus.BAD_REQUEST,
          "Username is already exists!.");
    }

    // add check for email exists in database
    if (userRepository.existsByEmail(registerDto.getUser().getEmail())) {
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
    Optional<User> user = this.userRepository.findUserByUsernameOrEmail(
        registerDto.getUser().getUsername().toLowerCase());
    if (user.isPresent()) {
      Optional<UserTenant> userTenant = this.userTenantRepository.findUserBy(user.get().getId(), tenant.get().getId());
      if (userTenant.isPresent()) {
        throw new CommonRuntimeException(
            HttpStatus.BAD_REQUEST,
            "User already exists and belongs to this tenant");
      }
    } else {
      this.createUserTenantData(
          registerDto.getUser(),
          UserStatus.ACTIVE,
          user.get().getId(),
          defaultRole.get().getId(),
          tenant.get().getId());
      return user.get();
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
    // try {
    // let creds: UserCredentials;
    // if (options?.authProvider) {
    // switch (options.authProvider) {
    // case 'keycloak': {
    // creds = new UserCredentials({
    // authProvider: 'keycloak',
    // authId: options?.authId,
    // });
    // break;
    // }
    // case 'internal':
    // default: {
    // const password = await bcrypt.hash(
    // process.env.USER_TEMP_PASSWORD,
    // saltRounds,
    // );
    // creds = new UserCredentials({
    // authProvider: 'internal',
    // password,
    // });
    // break;
    // }
    // }
    // } else {
    // const password = await bcrypt.hash(
    // process.env.USER_TEMP_PASSWORD,
    // saltRounds,
    // );
    // creds = new UserCredentials({
    // authProvider: 'internal',
    // password,
    // });
    // }
    // await this.credentials(user.id).create(creds, options);
    // } catch (err) {
    // // eslint-disable-next-line @typescript-eslint/no-floating-promises
    // super.deleteByIdHard(user.id);
    // throw new HttpErrors.UnprocessableEntity('Error while hashing password');
    // }
    // return user;
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
    // System.out.println(username);
    System.out.println("Reached 2");
    System.out.println(username.toLowerCase());
    Optional<User> user = this.userRepository.findUserByUsername(username.toLowerCase());
    System.out.println("Reached 3");

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
