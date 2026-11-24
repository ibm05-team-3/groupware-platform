package com.goodlifecoder.groupware.security.entity;

import com.goodlifecoder.groupware.user.entity.UserEntity;
import lombok.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * 이메일 로그인 주체.
 * getUsername 은 회원 id 문자열이다.
 * 계정 상태만 담고, 본사 역할은 담지 않는다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
public class CustomUserDetails implements UserDetails {

    private final String sub;
    private final List<GrantedAuthority> authorities;
    private final String password;
    private final boolean enabled;
    private final boolean accountNonLocked;

    /** 회원과 비밀번호 해시로 만든다. 소셜 전용 계정이면 비밀번호는 null. */
    public CustomUserDetails(UserEntity entity, String password) {
        this.sub = String.valueOf(entity.getId());
        this.password = password;
        this.enabled = entity.isEnabled();
        this.accountNonLocked = entity.isAccountNonLocked();
        this.authorities = List.of();
    }

    /** 회원 번호 문자열. 이메일이 아니다. */
    @Override
    public @NonNull String getUsername() {
        return sub;
    }

    /** 로그인 인증에는 쓰지 않는다. */
    @Override
    public @NonNull Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /** 이메일 로그인 계정이 없으면 null. */
    @Override
    public String getPassword() {
        return password;
    }

    /** 잠금이 아니면 true. */
    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    /** 탈퇴·비활성이 아니면 true. */
    @Override
    public boolean isEnabled() {
        return enabled;
    }
}