package com.mudassir.authenticationservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.mudassir.authenticationservice.service.impl.KeycloakAuthService;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@AllArgsConstructor
@RestController
@RequestMapping("/keycloak")
public class KeycloakController {

  private final KeycloakAuthService keycloakAuthService;

  @GetMapping("/auth-redirect-callback")
  public String authRedirectCallback(@RequestParam("code") String code) {
    return this.keycloakAuthService.login(code);
  }

  @GetMapping("/login")
  public void keycloak(HttpServletResponse httpServletResponse) {
    httpServletResponse.setHeader(
        "Location",
        "http://localhost:8080/realms/mlakdawala/protocol/openid-connect/auth?response_type=code&client_id=sourcefuse&scope=openid&redirect_uri=http://localhost:8081/keycloak/auth-redirect-callback");
    httpServletResponse.setStatus(302);
  }
}
