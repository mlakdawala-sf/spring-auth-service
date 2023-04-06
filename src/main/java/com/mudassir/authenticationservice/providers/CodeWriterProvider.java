package com.mudassir.authenticationservice.providers;

import java.util.UUID;

import org.springframework.stereotype.Service;

import com.mudassir.authenticationservice.models.JwtTokenRedis;
import com.mudassir.authenticationservice.repositories.JwtTokenRedisRepository;

import lombok.AllArgsConstructor;

@AllArgsConstructor
@Service
public class CodeWriterProvider {

  JwtTokenRedisRepository jwtTokenRedisRepository;

  public UUID provide(String token) {
    UUID uuid = UUID.randomUUID();
    JwtTokenRedis jwtTokenRedis = new JwtTokenRedis(uuid, token);
    this.jwtTokenRedisRepository.save(jwtTokenRedis);

    return uuid;
  }
}
