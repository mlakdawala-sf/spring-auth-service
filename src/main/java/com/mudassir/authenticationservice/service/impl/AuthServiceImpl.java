package com.mudassir.authenticationservice.service.impl;

import com.mudassir.authenticationservice.enums.*;
import com.mudassir.authenticationservice.enums.AuthErrorKeys;
import com.mudassir.authenticationservice.enums.AuthProvider;
import com.mudassir.authenticationservice.enums.AuthenticateErrorKeys;
import com.mudassir.authenticationservice.enums.RoleKey;
import com.mudassir.authenticationservice.enums.UserStatus;
import com.mudassir.authenticationservice.exception.CommonRuntimeException;
import com.mudassir.authenticationservice.models.*;
import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.models.Role;
import com.mudassir.authenticationservice.models.Tenant;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.models.UserCredential;
import com.mudassir.authenticationservice.models.UserTenant;
import com.mudassir.authenticationservice.payload.LoginDto;
import com.mudassir.authenticationservice.payload.RegisterDto;
import com.mudassir.authenticationservice.repositories.*;
import com.mudassir.authenticationservice.repositories.RoleRepository;
import com.mudassir.authenticationservice.repositories.TenantRepository;
import com.mudassir.authenticationservice.repositories.UserCredentialRepository;
import com.mudassir.authenticationservice.repositories.UserRepository;
import com.mudassir.authenticationservice.repositories.UserTenantRepository;
import com.mudassir.authenticationservice.security.JwtTokenProvider;
import com.mudassir.authenticationservice.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;

import java.util.Objects;
import java.util.Optional;

@Service
public class AuthServiceImpl implements AuthService {

    private AuthenticationManager authenticationManager;
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private TenantRepository tenantRepository;
    private PasswordEncoder passwordEncoder;
    private JwtTokenProvider jwtTokenProvider;

    private UserCredentialRepository userCredentialRepository;
    private UserTenantRepository userTenantRepository;
    private com.mudassir.authenticationservice.service.impl.LoginHelperService loginHelperService;


    public AuthServiceImpl(AuthenticationManager authenticationManager,
                           UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder,
                           JwtTokenProvider jwtTokenProvider,
                           UserCredentialRepository userCredentialRepository,
                           TenantRepository tenantRepository,
                           UserTenantRepository userTenantRepository,
                           com.mudassir.authenticationservice.service.impl.LoginHelperService loginHelperService

    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userCredentialRepository=userCredentialRepository;
        this.tenantRepository=tenantRepository;
        this.userTenantRepository=userTenantRepository;
        this.loginHelperService=loginHelperService;
    }

    @Override
    public String login(LoginDto loginDto, AuthClient authClient, User authUser) {
        this.loginHelperService.verifyClientUserLogin(loginDto,authClient,authUser);
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginDto.getUsername(), loginDto.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtTokenProvider.generateToken(authentication);

        return token;
    }

    @Override
    public String register(RegisterDto registerDto) {

        // add check for username exists in database
        if(userRepository.existsByUsername(registerDto.getUsername())){
            throw new CommonRuntimeException(HttpStatus.BAD_REQUEST, "Username is already exists!.");
        }

        // add check for email exists in database
        if(userRepository.existsByEmail(registerDto.getEmail())){
            throw new CommonRuntimeException(HttpStatus.BAD_REQUEST, "Email is already exists!.");
        }
        Role defaultRole = roleRepository.findByRoleType(RoleKey.Default.label);
        Tenant tenant = tenantRepository.findByKey("master");

        User user = new User();
        user.setFirstName(registerDto.getName());
        user.setUsername(registerDto.getUsername());
        user.setEmail(registerDto.getEmail());

        User savedUser=userRepository.save(user);

        UserTenant userTenant=new UserTenant();
        userTenant.setRoleId(defaultRole.getId());
        userTenant.setStatus(UserStatus.ACTIVE);
        userTenant.setTenantId(tenant.getId());
        userTenant.setUserId(savedUser.getId());


        UserCredential userCredential = new UserCredential();
        userCredential.setUserId(savedUser.getId());
        userCredential.setPassword(passwordEncoder.encode(registerDto.getPassword()));
        userCredential.setAuthProvider("internal");

        userTenantRepository.save(userTenant);
        userCredentialRepository.save(userCredential);


        return "User registered successfully!.";
    }

    @Override
    public Optional<User> verifyPassword(String username, String password) {
//System.out.println(username);
        System.out.println("Reached 2");
        System.out.println(username.toLowerCase());
         Optional<User> user =this.userRepository.findUserByUsername(username.toLowerCase());
        System.out.println("Reached 3");

        if (user.isEmpty() || user.get().getDeleted()) {
            throw new HttpServerErrorException(HttpStatus.UNAUTHORIZED, AuthenticateErrorKeys.UserDoesNotExist.label);
        }
        Optional<UserCredential> creds = this.userCredentialRepository.findByUserId(user.get().getId());
         if (creds.isPresent() && !creds.get().getPassword().isEmpty() ||
                 !Objects.equals(creds.get().getAuthProvider(), AuthProvider.INTERNAL) ||
                !(BCrypt.checkpw(password, creds.get().getPassword()))

    ) {
//            this.logger.error('User creds not found in DB or is invalid');
            throw new HttpServerErrorException(HttpStatus.UNAUTHORIZED, AuthErrorKeys.InvalidCredentials.label);

        } else {
            return user;
        }
    }
}
