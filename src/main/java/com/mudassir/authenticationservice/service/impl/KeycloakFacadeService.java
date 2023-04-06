package com.mudassir.authenticationservice.service.impl;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.mudassir.authenticationservice.payload.keycloak.KeycloakAuthResponse;
import com.mudassir.authenticationservice.payload.keycloak.KeycloakUserDTO;

@Component
public class KeycloakFacadeService {

  public KeycloakAuthResponse keycloakAuthByCode(String code) {
    String url = "http://localhost:8080/realms/mlakdawala/protocol/openid-connect/token";
    HttpHeaders headers = new HttpHeaders();
    headers.set("Accept", "*/*");
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
    map.add("client_id", "sourcefuse");
    map.add("client_secret", "HIfZOya6vPukf9BnMqyH4xrRKxLgGypE");
    map.add("code", code);
    map.add("redirect_uri", "http://localhost:8081/keycloak/auth-redirect-callback");
    map.add("grant_type", "authorization_code");

    HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
    RestTemplate restTemplate = new RestTemplate();
    ResponseEntity<KeycloakAuthResponse> response = restTemplate.postForEntity(
        url,
        request,
        KeycloakAuthResponse.class);
    return response.getBody();
  }

  public KeycloakUserDTO getKeycloakUserProfile(String accessToken) {
    String url = "http://localhost:8080/realms/mlakdawala/protocol/openid-connect/userinfo";
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(accessToken);
    HttpEntity request = new HttpEntity(headers);
    ResponseEntity<KeycloakUserDTO> response = restTemplate.exchange(
        url,
        HttpMethod.GET,
        request,
        KeycloakUserDTO.class);
    return response.getBody();
  }
}
