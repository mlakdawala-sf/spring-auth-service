package com.mudassir.authenticationservice.service;


import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.payload.LoginDto;
import com.mudassir.authenticationservice.payload.RegisterDto;

import java.util.Optional;

public interface AuthService {
    String login(LoginDto loginDto, AuthClient authClient, User authUser);

    String register(RegisterDto registerDto);

    Optional<User> verifyPassword(String username, String password);
}
