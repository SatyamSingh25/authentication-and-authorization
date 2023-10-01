package com.jwt.authenticationandauthorization.controller;

import com.jwt.authenticationandauthorization.dao.AuthRequest;
import com.jwt.authenticationandauthorization.dao.AuthResponse;
import com.jwt.authenticationandauthorization.entity.User;
import com.jwt.authenticationandauthorization.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody User user){
        return authService.register(user);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@RequestBody AuthRequest authRequest){
        return authService.signin(authRequest);
    }

}
