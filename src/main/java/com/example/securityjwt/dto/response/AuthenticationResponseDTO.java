package com.example.securityjwt.dto.response;

import lombok.Data;

@Data
public class AuthenticationResponseDTO {

	private String jwtToken;
	private String refreshToken;

}
