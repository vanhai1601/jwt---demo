package com.example.securityjwt.jwt;

import com.example.securityjwt.entity.Token;
import com.example.securityjwt.repository.TokenRepository;
import com.example.securityjwt.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JWTRequestFilter extends OncePerRequestFilter {
    @Autowired
    private TokenRepository tokenRepository;
    @Autowired
    private JWTTokenComponent jwtTokenComponent;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            final String requestToken = request.getHeader("Authorization");
            if (requestToken != null && requestToken.startsWith("Bearer ")) {
                String jwtToken = requestToken.substring(7);
                Token token = tokenRepository.findTokenByToken(jwtToken);
                String userName = jwtTokenComponent.getUserNameFromToken(jwtToken);
                SecurityContext securityContext = SecurityContextHolder.getContext();
                if (userName != null && securityContext.getAuthentication() == null && token != null) {
                    UserDetails userDetails = new User(userName, "", jwtTokenComponent.getRolesFromToken(jwtToken));
                    if (jwtTokenComponent.validateToken(jwtToken, userDetails)) {
                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());
                        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        securityContext.setAuthentication(authenticationToken);
                    }
                }
            }
        } catch (ExpiredJwtException ex) {
            request.setAttribute("expiredJwtException", ex);
        } catch (SignatureException ex) {
            request.setAttribute("signatureException",ex);
        } catch (BadCredentialsException ex) {
            request.setAttribute("badCredentialsException", ex);
        }
        filterChain.doFilter(request, response);
    }
}
