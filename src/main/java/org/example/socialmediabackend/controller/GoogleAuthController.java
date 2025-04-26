package org.example.socialmediabackend.controller;

import org.example.socialmediabackend.model.User;
import org.example.socialmediabackend.responses.LoginResponse;
import org.example.socialmediabackend.service.GoogleAuthService;
import org.example.socialmediabackend.service.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth/google")
public class GoogleAuthController {

    private final GoogleAuthService googleAuthService;
    private final JwtService jwtService;

    public GoogleAuthController(GoogleAuthService googleAuthService, JwtService jwtService) {
        this.googleAuthService = googleAuthService;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticateWithGoogle(@RequestParam String idToken) {
        User user = googleAuthService.authenticateWithGoogle(idToken);
        String jwtToken = jwtService.generateToken(user);
        LoginResponse loginResponse = new LoginResponse(jwtToken, jwtService.getExpirationTime());
        return ResponseEntity.ok(loginResponse);
    }
}