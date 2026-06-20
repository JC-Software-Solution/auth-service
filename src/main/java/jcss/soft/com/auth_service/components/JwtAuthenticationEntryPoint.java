package jcss.soft.com.auth_service.components;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jcss.soft.com.auth_service.dtos.response.ErrorResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.time.Instant;

/**
 * Note the import: Spring Boot 4 defaults to Jackson 3, whose classes live
 * under tools.jackson.* (renamed from com.fasterxml.jackson.* in Jackson 2).
 * Spring auto-configures a JsonMapper bean you can inject directly.
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final JsonMapper jsonMapper;

    public JwtAuthenticationEntryPoint(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ErrorResponse error = new ErrorResponse(
                Instant.now(), 401, "Unauthorized",
                "A valid Bearer token is required to access this resource",
                request.getRequestURI()
        );

        response.getWriter().write(jsonMapper.writeValueAsString(error));
    }
}