package com.example.securityjwt.entity;

import lombok.Data;

import javax.persistence.*;

@Entity
@Data
@Table(name = "token")
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "user_id")
    private int userId;
    @Column(name = "token")
    private String token;
    @Column(name = "refresh_token")
    private String refreshToken;

}
