package com.mudassir.authenticationservice.repositories;

import com.mudassir.authenticationservice.models.JwtTokenRedis;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

public interface JwtTokenRedisRepository extends CrudRepository<JwtTokenRedis, String> {}
