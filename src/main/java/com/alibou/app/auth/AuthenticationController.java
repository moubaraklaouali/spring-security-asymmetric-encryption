package com.alibou.app.auth;

import com.alibou.app.auth.request.RefreshRequest;
import com.alibou.app.auth.response.AuthenticationResponse;
import com.alibou.app.user.User;
import com.alibou.app.user.response.UserInfo;
import com.alibou.app.auth.request.AuthenticationRequest;
import com.alibou.app.auth.request.RegistrationRequest;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication API")
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @Valid @RequestBody final AuthenticationRequest request, HttpServletResponse response) {
        return ResponseEntity.ok(this.service.login(request, response));
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(
            @Valid @RequestBody final RegistrationRequest request) {
        this.service.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refresh(
            @RequestBody final RefreshRequest req,
            HttpServletRequest servletRequest,
            HttpServletResponse response) {
        return ResponseEntity.ok(this.service.refreshToken(req, servletRequest, response));
    }

    @PostMapping("/logout")
    public void logout(HttpServletResponse response) {
        this.service.logout(response);
    }

    @GetMapping("/profile")
    public UserInfo profile(final Authentication principal) {

        return this.service.getUserInfo(getUserCon(principal));
    }

    private User getUserCon(final Authentication authentication) {
        return ((User) authentication.getPrincipal());
    }

}
