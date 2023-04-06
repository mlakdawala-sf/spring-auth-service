package com.mudassir.authenticationservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.mudassir.authenticationservice.security.JwtAuthenticationEntryPoint;
import com.mudassir.authenticationservice.security.JwtAuthenticationFilter;

@Configuration
@EnableMethodSecurity
@EnableRedisRepositories
public class SecurityConfig {

  private JwtAuthenticationEntryPoint authenticationEntryPoint;
  private final KeycloakLogoutHandler keycloakLogoutHandler;

  private JwtAuthenticationFilter authenticationFilter;

  public SecurityConfig(
    JwtAuthenticationEntryPoint authenticationEntryPoint,
    JwtAuthenticationFilter authenticationFilter,
    KeycloakLogoutHandler keycloakLogoutHandler
  ) {
    this.authenticationEntryPoint = authenticationEntryPoint;
    this.authenticationFilter = authenticationFilter;
    this.keycloakLogoutHandler = keycloakLogoutHandler;
  }

  @Bean
  public static PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
    return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
      .authorizeHttpRequests(authorize ->
        authorize
          .requestMatchers("/auth/**", "/keycloak/**")
          .permitAll()
          .anyRequest()
          .authenticated()
      )
      .exceptionHandling(exception ->
        exception.authenticationEntryPoint(authenticationEntryPoint)
      );
    // .sessionManagement(session ->
    // session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    http
      .oauth2Login()
      .and()
      .logout()
      .addLogoutHandler(keycloakLogoutHandler)
      .logoutSuccessUrl("/");
    // http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

    // http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    http.cors().and().csrf().disable();

    http.addFilterBefore(
      authenticationFilter,
      UsernamePasswordAuthenticationFilter.class
    );
    return http.build();
  }

  @Bean
  public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
    return http.getSharedObject(AuthenticationManagerBuilder.class).build();
  }

  @Bean
  public LettuceConnectionFactory redisConnectionFactory() {
    RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(
      "localhost",
      6379
    );
    return new LettuceConnectionFactory(config);
  }

  @Bean
  public RedisTemplate<String, Object> redisTemplate() {
    RedisTemplate<String, Object> template = new RedisTemplate<>();
    template.setConnectionFactory(redisConnectionFactory());
    return template;
  }
}
