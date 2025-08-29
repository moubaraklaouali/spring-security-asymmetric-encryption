package com.alibou.app.user;

import com.alibou.app.user.request.ChangePasswordRequest;
import com.alibou.app.user.request.ProfileUpdateRequest;
import com.alibou.app.user.response.UserInfo;

import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {

    void updateProfileInfo(ProfileUpdateRequest request, String userId);

    void changePassword(ChangePasswordRequest request, String userId);

    void deactivateAccount(String userId);

    void reactivateAccount(String userId);

    void deleteAccount(String userId);


}
