package jcss.soft.com.auth_service.dtos.response;

import org.springframework.http.ResponseCookie;

public record CookiesResponse(
        ResponseCookie cookie,
        AuthenticationResponse authenticationResponse
) {
}
