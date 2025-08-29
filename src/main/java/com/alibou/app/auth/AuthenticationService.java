package com.alibou.app.auth;

import com.alibou.app.auth.request.AuthenticationRequest;
import com.alibou.app.auth.request.RefreshRequest;
import com.alibou.app.auth.request.RegistrationRequest;
import com.alibou.app.auth.response.AuthenticationResponse;
import com.alibou.app.user.User;
import com.alibou.app.user.response.UserInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthenticationService {

    AuthenticationResponse login(AuthenticationRequest request, HttpServletResponse response);

    void register(RegistrationRequest request);

    AuthenticationResponse refreshToken(RefreshRequest req, HttpServletRequest servletRequest,
            HttpServletResponse response);

    void logout(HttpServletResponse response);

    UserInfo getUserInfo(User user);
}
