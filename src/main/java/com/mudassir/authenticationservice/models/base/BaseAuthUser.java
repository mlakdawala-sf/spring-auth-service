package com.mudassir.authenticationservice.models.base;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


public interface BaseAuthUser<T> {

    public T getId();

    public void setId(T id);

    public String getUsername();

    public void setUsername(String username) ;

    public String getPassword();

    public void setPassword(String password);
}
