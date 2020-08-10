package com.cos.jwtex01.controller;

import java.util.List;

import javax.servlet.http.HttpSession;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cos.jwtex01.config.auth.SessionUser;
import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RestController // = new RestApiController();
@RequestMapping("api/v1") // 컨트롤러 진입 주소
@RequiredArgsConstructor // final과 붙어있는 필드의 생성자를 다 만들어줌 
//= @Autowired(spring 전용) = @Inject(spring 뿐만 아니라 모든 코드에서 적용)
//@CrossOrigin // CORS 허용 - 여기에 걸어두는 것은 비추. 필요한 메소드에만 걸어두기
public class RestApiController {

	private final UserRepository userRepository; // final - 초기화 해야하는 강제성 부여
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	// 모든 사람이 접근 가능
	@GetMapping("home")
	public String home() {
		return "<h1>home</h1>";
	}

	// 매니저만 접근 가능
	@GetMapping("manager/reports")
	public String reports() {
		return "<h1>reports</h1>";
	}

	// 관리자만 접근 가능
	@GetMapping("admin/users")
	public List<User> users() {
		return null;
	}

	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입 완료";
	}
	
	@GetMapping("user")
	public String user(HttpSession session) {
		SessionUser sessionUser = (SessionUser) session.getAttribute("sessionUser");
		System.out.println("principal : " + sessionUser.getId());
		System.out.println("principal : " + sessionUser.getUsername());
		System.out.println("principal : " + sessionUser.getRoles());
		return "<h1>user</h1>";
	}

}