package com.cos.jwtex01.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor

public class PrincipalDetailsService implements UserDetailsService{

	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("PrincipalDetailsService : 진입");
		User user = userRepository.findByUsername(username);
//		if(user != null) {
//			System.out.println("해당 회원을 찾았습니다.");
//			return new PrincipalDetails(user);
//		}
//		System.out.println("해당 회원을 찾지 못했습니다.");
//		return null;
		
		// session.setAttribute("loginUser", user); → @LoginUser 내가 어노테이션을 만들어서 사용하면 편함
		return new PrincipalDetails(user); // SecurityContext → 세션에 저장됨! @AuthenticationPrincipal 로 접근해야 함  
	}
}
