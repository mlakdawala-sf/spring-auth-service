package com.mudassir.authenticationservice.providers;

import com.mudassir.authenticationservice.enums.AuthErrorKeys;
import com.mudassir.authenticationservice.enums.AuthenticateErrorKeys;
import com.mudassir.authenticationservice.enums.UserStatus;
import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.models.UserTenant;
import com.mudassir.authenticationservice.payload.LoginDto;
import com.mudassir.authenticationservice.payload.VerificationProvider;
import com.mudassir.authenticationservice.repositories.AuthClientRepository;
import com.mudassir.authenticationservice.repositories.UserRepository;
import com.mudassir.authenticationservice.repositories.UserTenantRepository;
import com.mudassir.authenticationservice.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

@Service
public class ResourceOwnerVerifyProvider {
    private UserRepository userRepository;
    private UserTenantRepository userTenantRepository;
    private AuthClientRepository authClientRepository;
    private AuthService authService;

    public ResourceOwnerVerifyProvider(UserRepository userRepository, UserTenantRepository userTenantRepository, AuthClientRepository authClientRepository, AuthService authService) {
        this.userRepository = userRepository;
        this.userTenantRepository = userTenantRepository;
        this.authClientRepository = authClientRepository;
        this.authService = authService;
    }

    public VerificationProvider value(LoginDto loginDto) throws HttpServerErrorException{
       Optional<User> user;

        try {
            user =  this.authService.verifyPassword(loginDto.getUsername(), loginDto.getPassword());
            System.out.println("Reached 1");

        } catch (Exception error){
//        const otp: Otp = await this.otpRepository.get(username);
//            if (!otp || otp.otp !== password) {
//                throw new HttpErrors.Unauthorized(AuthErrorKeys.InvalidCredentials);
//            }
            System.out.println(error);

            user =  this.userRepository.findUserByUsername(loginDto.getUsername());
            if (user.isEmpty()) {
                throw new HttpServerErrorException(HttpStatus.UNAUTHORIZED, AuthErrorKeys.InvalidCredentials.label);
            }
        }
        UserTenant userTenant=this.userTenantRepository.findUserBy(user.get().getId(),user.get().getDefaultTenantId(), Arrays.asList(UserStatus.REJECTED, UserStatus.INACTIVE));
        if (userTenant==null) {
            throw new HttpServerErrorException(HttpStatus.UNAUTHORIZED, AuthenticateErrorKeys.UserInactive.label);
        }

      AuthClient client =  this.authClientRepository.findAuthClientByClientId(loginDto.getClient_id());
        if (client==null || user.get().getAuthClientIds().contains(client.getId())
        ) {
            throw new HttpServerErrorException(HttpStatus.UNAUTHORIZED, AuthErrorKeys.ClientInvalid.label);

        } else if (!Objects.equals(client.getClientSecret(),loginDto.getClient_secret())) {
            throw new HttpServerErrorException(HttpStatus.UNAUTHORIZED, AuthErrorKeys.ClientVerificationFailed.label);

        }

        return new VerificationProvider(client,user.get());
    }
}
