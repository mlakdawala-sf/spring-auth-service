package com.mudassir.authenticationservice.models.base;

import jakarta.persistence.Entity;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SoftDeleteEntity {
    Boolean deleted;
    Date deletedOn;
    String deletedBy;
}
