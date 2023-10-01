package com.jwt.authenticationandauthorization.dao;

import com.jwt.authenticationandauthorization.entity.User;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthResponse {
    private User user;
    private String token;
}
