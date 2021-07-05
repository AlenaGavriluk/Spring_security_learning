package com.binarystudio.academy.springsecurity.security.auth;

import com.binarystudio.academy.springsecurity.domain.user.UserService;
import com.binarystudio.academy.springsecurity.domain.user.model.User;
import com.binarystudio.academy.springsecurity.security.auth.model.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("auth")
public class AuthController {
	private final AuthService authService;
	private final UserService userService;

	public AuthController(AuthService authService, UserService userService) {
		this.userService = userService;
		this.authService = authService;
	}

	@PostMapping("safe/login")
	public AuthResponse login(@RequestBody AuthorizationRequest authorizationRequest) {
		return authService.performLogin(authorizationRequest);
	}

	@PostMapping("safe/register")
	public AuthResponse register(@RequestBody RegistrationRequest registrationRequest) {
		return authService.registerUser(registrationRequest);
	}

	@PostMapping("safe/refresh")
	public AuthResponse refreshTokenPair(@RequestBody RefreshTokenRequest refreshTokenRequest) {
		return authService.refreshToken(refreshTokenRequest.getRefreshToken());
	}

	@PutMapping("safe/forgotten_password")
	public void forgotPasswordRequest(@RequestParam String email) {
		User user = userService.loadUserByUsername(email);
		authService.sendPasswordChangeToken(user);
	}

	@PatchMapping("safe/forgotten_password")
	public AuthResponse forgottenPasswordReplacement(@RequestBody ForgottenPasswordReplacementRequest forgottenPasswordReplacementRequest) {
		return authService.replaceForgottenPassword(forgottenPasswordReplacementRequest);
	}

	@PatchMapping("change_password")
	public AuthResponse changePassword(@RequestBody PasswordChangeRequest passwordChangeRequest) {
		User user = userService.getCurrentUser();
		userService.changePassword(user, passwordChangeRequest.getNewPassword());
		return authService.getNewTokenPair(user);
	}

	@GetMapping("me")
	public User whoAmI(@AuthenticationPrincipal User user) {
		return user;
	}
}
