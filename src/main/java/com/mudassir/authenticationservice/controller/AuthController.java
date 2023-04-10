package com.mudassir.authenticationservice.controller;

import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.payload.*;
import com.mudassir.authenticationservice.providers.ClientPasswordVerifyProvider;
import com.mudassir.authenticationservice.providers.ResourceOwnerVerifyProvider;
import com.mudassir.authenticationservice.services.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthController {

  private final AuthService authService;
  private final ClientPasswordVerifyProvider clientPasswordVerifyProvider;

  private final ResourceOwnerVerifyProvider resourceOwnerVerifyProvider;

  @PostMapping("/token")
  public JWTAuthResponse getTokenByCode(@RequestBody AuthTokenRequest authTokenRequest) {
    return this.authService.getTokenByCode(authTokenRequest);
  }

  @PostMapping(value = { "/login", "/signin" })
  public ResponseEntity<CodeResponse> login(@RequestBody LoginDto loginDto) {
    AuthClient client =
      this.clientPasswordVerifyProvider.value(
          loginDto.getClient_id(),
          loginDto.getClient_secret()
        );
    UserVerificationDTO userVerificationDTO =
      this.resourceOwnerVerifyProvider.value(loginDto);

    String code = authService.login(loginDto, client, userVerificationDTO.getAuthUser());

    CodeResponse codeResponse = new CodeResponse();
    codeResponse.setCode(code);

    return ResponseEntity.ok(codeResponse);
  }
  // @PostMapping(value = { "/register", "/signup" })
  // public ResponseEntity<String> register(@RequestBody RegisterDto registerDto)
  // {
  // String response = authService.register(registerDto);
  // return new ResponseEntity<>(response, HttpStatus.CREATED);
  // }
}
