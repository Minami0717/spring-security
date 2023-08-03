package com.green.security.config.security;

import com.green.security.config.security.model.MyUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationFacade {
    public MyUserDetails getLoginUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return (MyUserDetails) auth.getPrincipal();
    }

    public Long getLoginUserPk() {
        return getLoginUser().getIuser();
    }
}
