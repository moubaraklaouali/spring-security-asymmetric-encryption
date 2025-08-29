package com.alibou.app.auth.impl;

import com.alibou.app.auth.AuthenticationService;
import com.alibou.app.auth.request.RefreshRequest;
import com.alibou.app.auth.request.AuthenticationRequest;
import com.alibou.app.auth.request.RegistrationRequest;
import com.alibou.app.auth.response.AuthenticationResponse;
import com.alibou.app.exception.BusinessException;
import com.alibou.app.role.Role;
import com.alibou.app.role.RoleRepository;
import com.alibou.app.security.JwtService;
import com.alibou.app.user.User;
import com.alibou.app.user.UserMapper;
import com.alibou.app.user.UserRepository;
import com.alibou.app.user.response.UserInfo;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

import static com.alibou.app.exception.ErrorCode.EMAIL_ALREADY_EXISTS;
import static com.alibou.app.exception.ErrorCode.PASSWORD_MISMATCH;
import static com.alibou.app.exception.ErrorCode.PHONE_ALREADY_EXISTS;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;

    @Override
    public AuthenticationResponse login(final AuthenticationRequest request, HttpServletResponse response) {
        final Authentication auth = this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()));
        final User user = (User) auth.getPrincipal();
        final String token = this.jwtService.generateAccessToken(user.getUsername());
        final String refreshToken = this.jwtService.generateRefreshToken(user.getUsername());
        final String tokenType = "Bearer";

        AuthenticationResponse authenticationResponse = AuthenticationResponse.builder()
                .accessToken(token)
                .refreshToken(refreshToken)
                .tokenType(tokenType)
                .build();
        setCookie(response, authenticationResponse);
        return authenticationResponse;
    }

    public void setCookie(HttpServletResponse response, AuthenticationResponse tokens) {
        // Cookie HttpOnly pour le refreshToken
        Cookie refreshTokenCookie = new Cookie("refreshToken", tokens.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int) jwtService.refreshTokenExpiration);
        // refreshTokenCookie.setSecure(true); // décommente si HTTPS
        response.addCookie(refreshTokenCookie);

        // Cookie HttpOnly pour l'accessToken
        Cookie accessTokenCookie = new Cookie("accessToken", tokens.getAccessToken());
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge((int) jwtService.accessTokenExpiration);
        // accessTokenCookie.setSecure(true); // décommente si HTTPS
        response.addCookie(accessTokenCookie);
    }

    @Override
    @Transactional
    public void register(final RegistrationRequest request) {
        checkUserEmail(request.getEmail());
        checkUserPhoneNumber(request.getPhoneNumber());
        checkPasswords(request.getPassword(), request.getConfirmPassword());

        final Role userRole = this.roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new EntityNotFoundException("Role user does not exist"));
        final List<Role> roles = new ArrayList<>();
        roles.add(userRole);

        final User user = this.userMapper.toUser(request);
        user.setRoles(roles);
        log.debug("Saving user {}", user);
        this.userRepository.save(user);

        final List<User> users = new ArrayList<>();
        users.add(user);
        userRole.setUsers(users);

        this.roleRepository.save(userRole);

    }

    @Override
    public AuthenticationResponse refreshToken(final RefreshRequest req, HttpServletRequest servletRequest,
            HttpServletResponse response) {

        String refreshToken = req.getRefreshToken();
        if (refreshToken == null || refreshToken.isEmpty()) {
            // Chercher dans les cookies
            if (servletRequest.getCookies() != null) {
                for (jakarta.servlet.http.Cookie cookie : servletRequest.getCookies()) {
                    if ("refreshToken".equals(cookie.getName())) {
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }
        }
        final String newAccessToken = this.jwtService.refreshAccessToken(refreshToken);
        final String tokenType = "Bearer";

        AuthenticationResponse authenticationResponse = AuthenticationResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .tokenType(tokenType)
                .build();
        setCookie(response, authenticationResponse);

        return authenticationResponse;
    }

    @Override
    public UserInfo getUserInfo(User user) {
        UserInfo userInfo = new UserInfo();
        BeanUtils.copyProperties(user, userInfo);
        return userInfo;
    }

    @Override
    public void logout(HttpServletResponse response) {
        // Invalider les cookies d'authentification en les expirant immédiatement
        Cookie refreshTokenCookie = new Cookie("refreshToken", null);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(0); // Expire immédiatement

        Cookie accessTokenCookie = new Cookie("accessToken", null);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0); // Expire immédiatement

        response.addCookie(refreshTokenCookie);
        response.addCookie(accessTokenCookie);
    }

    private void checkUserEmail(final String email) {
        final boolean emailExists = this.userRepository.existsByEmailIgnoreCase(email);
        if (emailExists) {
            throw new BusinessException(EMAIL_ALREADY_EXISTS);
        }
    }

    private void checkPasswords(final String password,
            final String confirmPassword) {
        if (password == null || !password.equals(confirmPassword)) {
            throw new BusinessException(PASSWORD_MISMATCH);
        }
    }

    private void checkUserPhoneNumber(final String phoneNumber) {
        final boolean phoneNumberExists = this.userRepository.existsByPhoneNumber(phoneNumber);
        if (phoneNumberExists) {
            throw new BusinessException(PHONE_ALREADY_EXISTS);
        }
    }
}
