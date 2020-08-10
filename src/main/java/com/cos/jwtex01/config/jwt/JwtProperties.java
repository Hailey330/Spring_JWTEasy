package com.cos.jwtex01.config.jwt;

public interface JwtProperties {
	String SECRET = "hongcha"; // 우리 서버만 알고 있는 비밀 값
	int EXPIRATION_TIME = 864000000; // = 10일(1/1000초)
	String TOKEN_PREFIX = "Bearer "; // 뒤에 한 칸 꼭 띄우기
	String HEADER_STRING = "Authorization";
}
