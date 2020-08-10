package com.cos.jwtex01.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.jwtex01.config.jwt.JwtAuthenticationFilter;
import com.cos.jwtex01.config.jwt.JwtAuthorizationFilter;
import com.cos.jwtex01.repository.UserRepository;

@Configuration
@EnableWebSecurity // 시큐리티 활성화 → 기본 스프링 필터 체인에 등록
public class SecurityConfig extends WebSecurityConfigurerAdapter{ // 필요한 것만 사용하기 위해서 Adapter
	
	@Autowired
	private UserRepository userRepository;
	
	@Bean // @Configuration이 IoC 등록할 때 @Bean 확인하고 등록됨 
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable() // csrf-token 사용 X 
			// .cors().disable() - 자바스크립트 공격 다 들어오니까 허용하지 말 것. 필요한 메소드만 부분적으로만 걸어두기 추천!
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Stateful 세션 유지, Stateless 세션 유지 X 
		.and()
			.formLogin().disable()
			.httpBasic().disable() // HTTP Jsession 막음
			.addFilter(new JwtAuthenticationFilter(authenticationManager())) // 내가 만든 필터 1 - formLogin, HTTP 기본 인증도 다 막아놨기 때문에 여기에 로그인 할 수 있게 작성
			.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository)) // 내가 만든 필터 2
			.authorizeRequests()
			.antMatchers("/api/v1/user/**")
				.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')") // user, manager, admin 접근 가능
			.antMatchers("/api/v1/manager/**")
				.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // 매니저, 관리자만 접근 가능
			.antMatchers("/api/v1/admin/**")
				.access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll();
	}
}