package com.cos.jwtex01.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.config.auth.SessionUser;
import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;

// 누가 들어갈 때 허락(인가)해줌. 앞에서는 인증! 지금은 인가
public class JwtAuthorizationFilter extends BasicAuthenticationFilter { // BasicAuthenticationFilter : Header 전문 필터

//	@Autowired 내가 new 한 클래스는 autowired 가 아무것도 안먹음
	private UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}

	// 서명하기
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// 1. 헤더 값 확인하기
		String header = request.getHeader(JwtProperties.HEADER_STRING);
		if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) { // 헤더 값이 널이거나 Bearer 가 없으면 튕겨보낼 것
			chain.doFilter(request, response);
		}
		System.out.println("header : " + header);

		// 2. jwt token 생성 시 체크할 것 ① 공백 X ② =, == 패딩 값 X
		String token = request.getHeader(JwtProperties.HEADER_STRING) // 위에서 검증했기 떄문에 값이 무조건 있음
				.replace(JwtProperties.TOKEN_PREFIX, "") // Bearer 날리기
				.replace(" ", "").replace("=", "");

		// token 구조 - a.b.c
		// 3. 토큰 검증하기 : Base64로 인코딩된 a와 b를 합쳐서 secret 값을 붙여서 해시한 뒤, 날아온 token의 c를 디코딩한
		// 값과 비교했을 때 같으면 검증 Ok!
		// → 이게 인증이기 때문에 AuthenticationManager도 필요 없음
		// 내가 SecurityContext에 직접 접근해서 세션을 만들 떄 자동으로 UserDetailsService에 있는
		// loadUserByUsername을 찾음
		String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token)
				.getClaim("username").asString(); // username 가져와야 UserDetailsService 타기 편함
		System.out.println("username ::: " + username);

		if (username != null) {
			System.out.println("1");
			User user = userRepository.findByUsername(username);

			// 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해
			// 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
			PrincipalDetails principalDetails = new PrincipalDetails(user);
			// 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
			// 패스워드는 모르니까 null처리, 어차피 지금 인증하는게 아니니까!
			// 강제로 시큐리티의 세션에 접근하여 값 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
			System.out.println("2");
			SessionUser sessionUser = SessionUser.builder().id(user.getId()).username(user.getUsername())
					.roles(user.getRoleList()).build();
			System.out.println("3");
			HttpSession session = request.getSession();
			System.out.println("JWT 검증 ::: " + session);
			session.setAttribute("sessionUser", sessionUser);
		}

		chain.doFilter(request, response);

		// authentication 객체가 만들어진다고 해서 세션이 만들어지는 것이 아니다.
		// SecurityContextHolder.getContext().setAuthentication(authentication); // 세션
		// 생성 완료
	}
}