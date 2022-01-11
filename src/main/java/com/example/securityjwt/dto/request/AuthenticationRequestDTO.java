package com.example.securityjwt.dto.request;

import lombok.Data;

@Data
public class AuthenticationRequestDTO {
	private String userName;
	private String password;

}
