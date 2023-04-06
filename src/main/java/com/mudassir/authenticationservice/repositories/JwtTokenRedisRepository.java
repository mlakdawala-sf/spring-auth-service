package com.mudassir.authenticationservice.repositories;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.mudassir.authenticationservice.models.JwtTokenRedis;

public interface JwtTokenRedisRepository extends CrudRepository<JwtTokenRedis, String> {}
