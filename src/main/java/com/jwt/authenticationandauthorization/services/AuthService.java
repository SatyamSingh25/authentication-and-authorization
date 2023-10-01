package com.jwt.authenticationandauthorization.services;

import com.jwt.authenticationandauthorization.dao.AuthRequest;
import com.jwt.authenticationandauthorization.dao.AuthResponse;
import com.jwt.authenticationandauthorization.entity.Role;
import com.jwt.authenticationandauthorization.entity.User;
import com.jwt.authenticationandauthorization.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;


    public ResponseEntity<?> register(User user) {
        Optional<User> userExist = userRepository.findByEmail(user.getEmail());
        if(userExist.isPresent())
            return new ResponseEntity<>("Already exist", HttpStatus.BAD_REQUEST);

        User newUser = User.builder()
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .password(passwordEncoder.encode(user.getPassword()))
//                .role(Role.USER)
                .build();

        newUser = userRepository.save(newUser);
        String generateToken = jwtService.generateToken(newUser);

        return new ResponseEntity<>(AuthResponse.builder()
                .user(newUser)
                .token(generateToken)
                .build(), HttpStatus.CREATED);
    }

    public ResponseEntity<?> signin(AuthRequest authRequest) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authRequest.getEmail(),
                        authRequest.getPassword()
                )
        );

        Optional<User> user = userRepository.findByEmail(authRequest.getEmail());
        if(user.isEmpty())
            return new ResponseEntity<>("Login Failed", HttpStatus.UNAUTHORIZED);

        String token = jwtService.generateToken(user.get());

        return new ResponseEntity<>(AuthResponse.builder()
                .user(user.get())
                .token(token)
                .build(), HttpStatus.ACCEPTED);

    }
}
