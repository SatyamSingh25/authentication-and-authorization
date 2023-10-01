package com.jwt.authenticationandauthorization.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Demo {
    @GetMapping("/hi")
    public String Hi(){
        return "Hello World";
    }
}
