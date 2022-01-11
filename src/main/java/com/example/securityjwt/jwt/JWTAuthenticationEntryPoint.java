package com.example.securityjwt.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

@Component
public class JWTAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Exception expiredJwtException = (Exception) request.getAttribute("expiredJwtException");
        Exception signatureException = (Exception) request.getAttribute("signatureException");
        String message;
        if (expiredJwtException != null) {
            message = "Token hết hiệu lực";
            byte[] body = new ObjectMapper().writeValueAsBytes(Collections.singletonMap("error", message));
            response.getOutputStream().write(body);
        } else if (signatureException != null) {
            message = "Token không chính xác";
            byte[] body = new ObjectMapper().writeValueAsBytes(Collections.singletonMap("error", message));
            response.getOutputStream().write(body);
        }
    }
}
