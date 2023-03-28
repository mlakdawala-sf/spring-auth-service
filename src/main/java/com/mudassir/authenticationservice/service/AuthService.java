package com.mudassir.authenticationservice.service;

import java.util.Optional;

import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.payload.LoginDto;
import com.mudassir.authenticationservice.payload.RegisterDto;

public interface AuthService {
  String login(LoginDto loginDto, AuthClient authClient, User authUser);

  String register(RegisterDto registerDto);

  Optional<User> verifyPassword(String username, String password);
}
