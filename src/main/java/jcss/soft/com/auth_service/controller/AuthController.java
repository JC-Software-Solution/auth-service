package jcss.soft.com.auth_service.controller;

import jcss.soft.com.auth_service.components.AuthCookies;
import jcss.soft.com.auth_service.dtos.request.AuthenticateRequest;
import jcss.soft.com.auth_service.dtos.request.RegisterRequest;
import jcss.soft.com.auth_service.dtos.response.AuthenticationResponse;
import jcss.soft.com.auth_service.dtos.response.CookiesResponse;
import jcss.soft.com.auth_service.dtos.response.ResponseObject;
import jcss.soft.com.auth_service.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthCookies authCookies;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {

        CookiesResponse response = authCookies.register(request);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, response.cookie().toString())
                .body(response.authenticationResponse());

    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticateRequest request) {
        CookiesResponse response = authCookies.authenticate(request);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, response.cookie().toString())
                .body(response.authenticationResponse());
    }


    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, authCookies.logout().toString())
                .build();
    }
}