package com.mudassir.authenticationservice.models.base;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class BaseEntity extends  SoftDeleteEntity {
    Date createdOn;
    Date modifiedOn;
}
