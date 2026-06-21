package jcss.soft.com.auth_service.components;

import jcss.soft.com.auth_service.dtos.request.AuthenticateRequest;
import jcss.soft.com.auth_service.dtos.request.RegisterRequest;
import jcss.soft.com.auth_service.dtos.response.AuthenticationResponse;
import jcss.soft.com.auth_service.dtos.response.CookiesResponse;
import jcss.soft.com.auth_service.dtos.response.ResponseObject;
import jcss.soft.com.auth_service.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthCookies {
    private final AuthenticationService service;

    public CookiesResponse register(RegisterRequest request) {
        AuthenticationResponse response =  service.register(request);

        return  buildCookie(response);
    }


    public CookiesResponse authenticate(AuthenticateRequest request) {
        AuthenticationResponse response =  service.authenticate(request);

        return  buildCookie(response);
    }


    public ResponseCookie logout() {
        return ResponseCookie.from("X-ACCESS-TOKEN", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0)
                .sameSite("Strict")
                .build();
    }

    private CookiesResponse buildCookie(AuthenticationResponse response) {
        ResponseCookie cookie = ResponseCookie.from("X-ACCESS-TOKEN", response.getToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(24 * 60 * 60)
                .sameSite("Strict")
                .build();
        response.setToken(null);

        return new CookiesResponse(cookie, response);
    }

}
