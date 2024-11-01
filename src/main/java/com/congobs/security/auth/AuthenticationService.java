package com.congobs.security.auth;

import com.congobs.security.config.JwtService;
import com.congobs.security.models.Role;
import com.congobs.security.models.User;
import com.congobs.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {

        User createdUser = User.builder()
                               .firstname(request.getFirstname())
                               .lastname(request.getLastname())
                               .email(request.getEmail())
                               .password(passwordEncoder.encode(request.getPassword()))
                               .role(Role.USER)
                               .build();
        userRepository.save(createdUser);
        String generatedJWTToken = jwtService.generateJWTToken(createdUser.getEmail());
        return new AuthenticationResponse(generatedJWTToken);
    }

    public AuthenticationResponse login(LoginRequest request) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request.getPassword()
            )
        );
        User registredUser = userRepository.findByEmail(request.getEmail()).orElseThrow(
            () -> new UsernameNotFoundException("User not found"));
        String generatedJWTToken = jwtService.generateJWTToken(registredUser.getEmail());
        return new AuthenticationResponse(generatedJWTToken);
    }
}
