package com.cos.jwtex01.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.config.dto.LoginRequestDto;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;

	// Authentication 객체 만들어서 리턴 - 필터 체인 돌아서 다시 request
	// 인증 요청 시 실행되는 함수 → /login
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		// request에 있는 username, password 를 파싱해서 Obejct로 뽑아내기
		ObjectMapper om = new ObjectMapper(); // json, form data, string 을 다 Object 로 변환해주는 함수
		LoginRequestDto loginRequestDto = null;
		try {
			loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("JwtAuthenticationFilter : 토큰 생성 완료");
		
		// UsernamePassword 토큰 생성
		UsernamePasswordAuthenticationToken authenticationToken = 
				new UsernamePasswordAuthenticationToken(
						loginRequestDto.getUsername(), 
						loginRequestDto.getPassword()
				);
		
		// Authenticate() 함수가 호출되면 AuthenticationProvider가 UserDetailsService의 loadUserByUsername(Token의 첫 번째 파라미터)를 호출함
		// UserDetails-Request를 리턴 받아서 Token의 두 번째 파라미터(credential)과 UserDetails-DB의 getPassword() 함수로 비교해서 동일하면 
		// Authentication 객체를 만들어서 필터 체인으로 리턴해준다. 
		
		// ★ tip! AuthenticationProvider의 디폴트 서비스는 UserDetailsService 타입 
		// ★ tip! AuthenticationProvider의 디폴트 암호화 방식은 BCryptPasswordEncoder 
		// AuthenticationProvider에게 따로 알려줄 필요가 없음!
		
		// Authentication 객체는 AuthenticationProvider에 넘어간 UserDetailsService를 통해서 생성한다. 
		Authentication authentication = 
				authenticationManager.authenticate(authenticationToken);
		
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("Authentication : " + principalDetails.getUser().getUsername());
		return authentication;
	}

	// JWT Token 생성 후 응답 - response header에 정보만 담아준다. → AuthenticationManager 에게 의존
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		// authResult 는 Authentication 객체 
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		String jwtToken = JWT.create()
				// 페이로드 - ① 등록된 클레임(이미 정해진 클레임) 
				// 필수 : iss(토큰 발급자), sub(토큰 제목), exp(토큰 만료시간)
				// ② 공개 클레임 
				// ★ ③ 비공개 클레임 : 개인정보, 비밀번호 제외한 Id, Primary Key, Scope 등을 넣음 
				// https://velopert.com/2389 
				.withSubject(principalDetails.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+864000000)) // 864000000 = 10일 
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("hongcha".getBytes())); // getBytes() 더 쪼개야 보안이 좋음

		response.addHeader("Authorization", "Bearer" + jwtToken);
	}

}
