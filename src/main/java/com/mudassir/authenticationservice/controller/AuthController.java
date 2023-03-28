package com.mudassir.authenticationservice.controller;

import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.payload.JWTAuthResponse;
import com.mudassir.authenticationservice.payload.LoginDto;
import com.mudassir.authenticationservice.payload.RegisterDto;
import com.mudassir.authenticationservice.payload.VerificationProvider;
import com.mudassir.authenticationservice.providers.ClientPasswordVerifyProvider;
import com.mudassir.authenticationservice.providers.ResourceOwnerVerifyProvider;
import com.mudassir.authenticationservice.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private AuthService authService;
    private ClientPasswordVerifyProvider clientPasswordVerifyProvider;

    private ResourceOwnerVerifyProvider resourceOwnerVerifyProvider;

    public AuthController(AuthService authService, ClientPasswordVerifyProvider clientPasswordVerifyProvider, ResourceOwnerVerifyProvider resourceOwnerVerifyProvider) {
        this.authService = authService;
        this.clientPasswordVerifyProvider = clientPasswordVerifyProvider;
        this.resourceOwnerVerifyProvider = resourceOwnerVerifyProvider;
    }

    // Build Login REST API
    @PostMapping(value = {"/login", "/signin"})
    public ResponseEntity<JWTAuthResponse> login(@RequestBody LoginDto loginDto){
        AuthClient client=this.clientPasswordVerifyProvider.value(loginDto.getClient_id(),loginDto.getClient_secret());
        VerificationProvider verificationProvider=this.resourceOwnerVerifyProvider.value(loginDto);

        String token = authService.login(loginDto,client,verificationProvider.getAuthUser());

        JWTAuthResponse jwtAuthResponse = new JWTAuthResponse();
        jwtAuthResponse.setAccessToken(token);

        return ResponseEntity.ok(jwtAuthResponse);
    }

    // Build Register REST API
    @PostMapping(value = {"/register", "/signup"})
    public ResponseEntity<String> register(@RequestBody RegisterDto registerDto){
        String response = authService.register(registerDto);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }
}