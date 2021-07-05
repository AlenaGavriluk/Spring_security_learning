package com.binarystudio.academy.springsecurity.security.auth;

import com.binarystudio.academy.springsecurity.domain.user.UserService;
import com.binarystudio.academy.springsecurity.domain.user.model.User;
import com.binarystudio.academy.springsecurity.security.auth.model.AuthResponse;
import com.binarystudio.academy.springsecurity.security.auth.model.AuthorizationRequest;
import com.binarystudio.academy.springsecurity.security.auth.model.ForgottenPasswordReplacementRequest;
import com.binarystudio.academy.springsecurity.security.auth.model.RegistrationRequest;
import com.binarystudio.academy.springsecurity.security.jwt.JwtException;
import com.binarystudio.academy.springsecurity.security.jwt.JwtProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {
	private final UserService userService;
	private final JwtProvider jwtProvider;
	private final PasswordEncoder passwordEncoder;

	public AuthService(UserService userService, JwtProvider jwtProvider, PasswordEncoder passwordEncoder) {
		this.userService = userService;
		this.jwtProvider = jwtProvider;
		this.passwordEncoder = passwordEncoder;
	}

	public AuthResponse performLogin(AuthorizationRequest authorizationRequest) {
		var userDetails = userService.loadUserByUsername(authorizationRequest.getUsername());
		if (passwordsDontMatch(authorizationRequest.getPassword(), userDetails.getPassword())) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid password");
		}
		return AuthResponse.of(jwtProvider.generateAccessToken(userDetails),
				jwtProvider.generateRefreshToken(userDetails));
	}

	private boolean passwordsDontMatch(String rawPw, String encodedPw) {
		return !passwordEncoder.matches(rawPw, encodedPw);
	}

	public AuthResponse registerUser(RegistrationRequest registrationRequest) {
		User newUser = userService.createNewUser(registrationRequest.getEmail(), registrationRequest.getLogin(),
				registrationRequest.getPassword());
		return AuthResponse.of(jwtProvider.generateAccessToken(newUser),
				jwtProvider.generateRefreshToken(newUser));
	}

	public AuthResponse refreshToken(String refreshToken) throws JwtException {
		String userName = jwtProvider.validateAndDeleteRefreshToken(refreshToken)
				.orElseThrow(() -> new JwtException("Invalid token", "jwt-invalid"));
		User user = userService.loadUserByUsername(userName);
		return getNewTokenPair(user);
	}

	public AuthResponse getNewTokenPair(User user){
		return AuthResponse.of(jwtProvider.generateAccessToken(user), jwtProvider.generateRefreshToken(user));
	}

	public void sendPasswordChangeToken(User user) {
		System.out.println(jwtProvider.generatePasswordChangeToken(user));
	}

	public AuthResponse replaceForgottenPassword(ForgottenPasswordReplacementRequest forgottenPasswordReplacementRequest) {
		String userName = jwtProvider.validateAndDeletePasswordChangeToken(forgottenPasswordReplacementRequest.getToken())
				.orElseThrow(() -> new JwtException("Invalid token", "jwt-invalid"));
		User user = userService.loadUserByUsername(userName);
		userService.changePassword(user, forgottenPasswordReplacementRequest.getNewPassword());
		return getNewTokenPair(user);
	}
}
