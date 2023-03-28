package com.mudassir.authenticationservice.models.base;

import java.util.Date;

import jakarta.persistence.Entity;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SoftDeleteEntity {

  Boolean deleted;
  Date deletedOn;
  String deletedBy;
}
