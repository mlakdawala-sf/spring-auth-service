package com.mudassir.authenticationservice.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.mudassir.authenticationservice.models.Role;
import com.mudassir.authenticationservice.models.User;
import com.mudassir.authenticationservice.models.UserCredential;
import com.mudassir.authenticationservice.models.UserTenant;
import com.mudassir.authenticationservice.repositories.RoleRepository;
import com.mudassir.authenticationservice.repositories.UserCredentialRepository;
import com.mudassir.authenticationservice.repositories.UserRepository;
import com.mudassir.authenticationservice.repositories.UserTenantRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

  private UserRepository userRepository;
  private UserTenantRepository userTenantRepository;
  private UserCredentialRepository userCredentialRepository;
  private RoleRepository roleRepository;

  public CustomUserDetailsService(
    UserRepository userRepository,
    UserTenantRepository userTenantRepository,
    UserCredentialRepository userCredentialRepository,
    RoleRepository roleRepository
  ) {
    this.userRepository = userRepository;
    this.userTenantRepository = userTenantRepository;
    this.userCredentialRepository = userCredentialRepository;
    this.roleRepository = roleRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String usernameOrEmail)
    throws UsernameNotFoundException {
    User user = userRepository
      .findByEmail(usernameOrEmail)
      .orElseThrow(() ->
        new UsernameNotFoundException(
          "User not found with username or email: " + usernameOrEmail
        )
      );
    UserTenant userTenant = userTenantRepository.findUserTenantByUserId(user.getId());
    Optional<UserCredential> userCredential = userCredentialRepository.findByUserId(
      user.getId()
    );

    Role role = roleRepository
      .findById(userTenant.getRoleId())
      .orElseThrow(() ->
        new UsernameNotFoundException(
          "Role not found by role id: " + userTenant.getRoleId()
        )
      );
    GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(role.getName());
    List<GrantedAuthority> listAuthorities = new ArrayList<GrantedAuthority>();
    listAuthorities.add(grantedAuthority);
    return new org.springframework.security.core.userdetails.User(
      user.getEmail(),
      userCredential.get().getPassword(),
      listAuthorities
    );
  }
}
