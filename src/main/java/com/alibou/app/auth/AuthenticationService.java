package com.alibou.app.auth;

import com.alibou.app.auth.request.AuthenticationRequest;
import com.alibou.app.auth.request.RefreshRequest;
import com.alibou.app.auth.request.RegistrationRequest;
import com.alibou.app.auth.response.AuthenticationResponse;

public interface AuthenticationService {

    AuthenticationResponse login(AuthenticationRequest request);

    void register(RegistrationRequest request);

    AuthenticationResponse refreshToken(RefreshRequest req);
}
