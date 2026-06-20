package jcss.soft.com.auth_service.controller;

import jcss.soft.com.auth_service.dtos.request.AuthenticateRequest;
import jcss.soft.com.auth_service.dtos.request.RegisterRequest;
import jcss.soft.com.auth_service.dtos.response.AuthenticationResponse;
import jcss.soft.com.auth_service.dtos.response.ResponseObject;
import jcss.soft.com.auth_service.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseObject register(@RequestBody RegisterRequest request) {

        return service.register(request);

    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticateRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }
}