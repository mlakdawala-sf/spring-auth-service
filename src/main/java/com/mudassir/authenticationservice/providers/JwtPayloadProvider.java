package com.mudassir.authenticationservice.providers;

import com.mudassir.authenticationservice.models.User;
import org.springframework.stereotype.Service;

@Service
public class JwtPayloadProvider {

  User provide(User user) {
    return user;
  }
}
