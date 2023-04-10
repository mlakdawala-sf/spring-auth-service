package com.mudassir.authenticationservice.models;

import jakarta.persistence.Id;
import java.io.Serializable;
import java.util.UUID;
import lombok.*;
import org.springframework.data.redis.core.RedisHash;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@RedisHash("JwtTokenRedis")
public class JwtTokenRedis implements Serializable {

  @Id
  private UUID id;

  private String token;
}
