package com.example.securityjwt.entity;

import lombok.Data;

import javax.persistence.*;

@Entity
@Data
@Table(name = "role")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(name = "code")
    private String code;
    @Column(name = "name")
    private String name;
}
