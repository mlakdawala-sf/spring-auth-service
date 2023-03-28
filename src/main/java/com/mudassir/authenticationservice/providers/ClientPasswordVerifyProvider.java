package com.mudassir.authenticationservice.providers;

import com.mudassir.authenticationservice.models.AuthClient;
import com.mudassir.authenticationservice.repositories.AuthClientRepository;
import org.springframework.stereotype.Service;

@Service
public class ClientPasswordVerifyProvider {
    private AuthClientRepository authClientRepository;

    public ClientPasswordVerifyProvider(AuthClientRepository authClientRepository) {
        this.authClientRepository = authClientRepository;
    }
    public AuthClient value(String clientId,String clientSecret){
        return this.authClientRepository.findAuthClientByClientIdAndClientSecret(clientId,clientSecret);
    }
}
