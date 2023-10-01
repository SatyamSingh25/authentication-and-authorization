package com.jwt.authenticationandauthorization.dao;

import lombok.*;

@Data
@Builder
@Getter @Setter
@AllArgsConstructor @NoArgsConstructor
public class AuthRequest {
    private String email;
    private String password;

}
