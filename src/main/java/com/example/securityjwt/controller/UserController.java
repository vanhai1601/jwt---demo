package com.example.securityjwt.controller;

import com.example.securityjwt.dto.request.AuthenticationRequestDTO;
import com.example.securityjwt.dto.request.UserRequest;
import com.example.securityjwt.dto.response.AuthenticationResponseDTO;
import com.example.securityjwt.entity.Token;
import com.example.securityjwt.entity.User;
import com.example.securityjwt.jwt.JWTTokenComponent;
import com.example.securityjwt.repository.TokenRepository;
import com.example.securityjwt.repository.UserRepository;
import com.example.securityjwt.service.JWTUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import javax.servlet.ServletException;
import java.io.IOException;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JWTUserDetailsService jwtUserDetailsService;
    @Autowired
    private JWTTokenComponent jwtTokenComponent;
    @Autowired
    private TokenRepository tokenRepository;


    @PostMapping("/register")
    public User registerUser(@RequestBody UserRequest userRequest) {
        User user = new User();
        user.setUserName(userRequest.getUserName());
        user.setRolesId(userRequest.getRolesId());
        user.setEmail(userRequest.getEmail());
        user.setPhoneNumber(userRequest.getPhoneNumber());
        user.setStatus(1);
        user.setPassword(userRequest.getPassword());
        encryptPassword(user);
        userRepository.save(user);
        return user;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthenticationRequestDTO dto) {
        try {
            authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(dto.getUserName(), dto.getPassword()));
            UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(dto.getUserName());
            String token = jwtTokenComponent.generateToken(userDetails);
            String refreshToken = jwtTokenComponent.doGenerateRefreshToken(userDetails);
            String userName = jwtTokenComponent.getUserNameFromToken(token);
            User user = userRepository.findUserByUserName(userName);
            Token tokenBO = tokenRepository.findTokenByUserId(user.getId());
            if (tokenBO == null) {
                tokenBO = new Token();
            }
            tokenBO.setToken(token);
            tokenBO.setRefreshToken(refreshToken);
            tokenBO.setUserId(user.getId());
            tokenRepository.save(tokenBO);
            AuthenticationResponseDTO authenticationResponseDTO = new AuthenticationResponseDTO();
            authenticationResponseDTO.setJwtToken(token);
            authenticationResponseDTO.setRefreshToken(refreshToken);
            return ResponseEntity.ok(authenticationResponseDTO);
        } catch (BadCredentialsException e) {
            return ResponseEntity.badRequest().body("Tên đăng nhập hoặc tài khoản không chính xác");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody String refreshToken) throws ServletException, IOException {
        Token tokenBO = tokenRepository.findTokenByRefreshToken(refreshToken);
        try {
            if (tokenBO != null) {
                User user = userRepository.findUserById(tokenBO.getUserId());
                UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(user.getUserName());
                jwtTokenComponent.validateToken(tokenBO.getToken(), userDetails);
                return ResponseEntity.ok("token chưa hết hiệu lực");
            } else {
                return ResponseEntity.badRequest().body("refreshtoken không đúng hoặc hết hiệu lực");
            }
        } catch (ExpiredJwtException ex) {
            User user = userRepository.findUserById(tokenBO.getUserId());
            UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(user.getUserName());
            String token = jwtTokenComponent.generateToken(userDetails);
            String refreshTokenNew = jwtTokenComponent.doGenerateRefreshToken(userDetails);
            tokenBO.setToken(token);
            tokenBO.setRefreshToken(refreshTokenNew);
            tokenRepository.save(tokenBO);
            AuthenticationResponseDTO authenticationResponseDTO = new AuthenticationResponseDTO();
            authenticationResponseDTO.setJwtToken(token);
            authenticationResponseDTO.setRefreshToken(refreshTokenNew);
            return ResponseEntity.ok(authenticationResponseDTO);
        }
    }

    @GetMapping("/all")
    @Secured({"ROLE_ADMIN"})
    public ResponseEntity<?> getListUser(){
        return ResponseEntity.ok(userRepository.findAll());
    }
    private void encryptPassword(User user) {
        String rawPassword = user.getPassword();
        if (rawPassword != null) {
            user.setPassword(passwordEncoder.encode(rawPassword));
        }
    }
}
