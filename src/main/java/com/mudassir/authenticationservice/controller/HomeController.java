package com.mudassir.authenticationservice.controller;


import com.mudassir.authenticationservice.models.*;
import com.mudassir.authenticationservice.repositories.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("home")
public class HomeController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserCredentialRepository userCredentialRepository;
    @Autowired
    private TenantRepository tenantRepository;
    @Autowired
    private UserTenantRepository userTenantRepository;

    @Autowired
    private AuthClientRepository authClientRepository;
    private static final String template = "Hello, %s!";



    @GetMapping("/users")
    public ResponseEntity<Iterable<User>> users() {
        Iterable<User> users = userRepository.findAll();
        return ResponseEntity.ok().body(users);
    }

    @GetMapping("/roles")
    public ResponseEntity<Iterable<Role>> roles() {
        Iterable<Role> roles = roleRepository.findAll();
        return ResponseEntity.ok().body(roles);
    }

    @GetMapping("/user-credentials")
    public ResponseEntity<Iterable<UserCredential>> userCredentials() {
        Iterable<UserCredential> userCredentials = userCredentialRepository.findAll();
        return ResponseEntity.ok().body(userCredentials);
    }

    @GetMapping("/tenants")
    public ResponseEntity<Iterable<Tenant>> tenants() {
        Iterable<Tenant> roles = tenantRepository.findAll();
        return ResponseEntity.ok().body(roles);
    }

    @GetMapping("/user-tenants")
    public ResponseEntity<Iterable<UserTenant>> userTenants() {
        Iterable<UserTenant> roles = userTenantRepository.findAll();
        return ResponseEntity.ok().body(roles);
    }
}
