package com.mudassir.authenticationservice.providers;

import org.springframework.stereotype.Service;

import com.mudassir.authenticationservice.models.User;

@Service
public class JwtPayloadProvider {

  User provide(User user) {
    return user;
  }
}
