package com.mudassir.authenticationservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class MyController {

  @GetMapping("/test")
  // @RolesAllowed("user")
  public String myEndpoint() {
    return "Hello, World!";
  }
}
