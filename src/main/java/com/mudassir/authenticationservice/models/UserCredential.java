package com.mudassir.authenticationservice.models;

import com.mudassir.authenticationservice.models.base.UserModifiableEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name="user_credentials",schema = "main")
public class UserCredential extends UserModifiableEntity
{
    @Id
    @GeneratedValue(strategy= GenerationType.UUID)
    private String id;

    private String authProvider;
    private String authId;
    private String authToken;
    private String password;
    private UUID userId;
}
