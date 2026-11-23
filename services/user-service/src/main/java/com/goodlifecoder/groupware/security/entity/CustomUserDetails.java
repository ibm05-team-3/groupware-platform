package com.goodlifecoder.groupware.security.entity;

import com.goodlifecoder.groupware.security.jwt.AccessTokenClaims;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import lombok.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * 이메일 로그인 주체.
 * getUsername 은 회원 id 문자열이다.
 * 액세스 토큰에는 본사 역할 코드와 권한을 싣는다. 본사 토큰에는 tenant_id 가 없다.
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
    private final List<String> roles;
    private final List<String> permissions;

    /** 회원, 비밀번호 해시, 본사 역할과 권한으로 만든다. 소셜 전용 계정이면 비밀번호는 null. */
    public CustomUserDetails(UserEntity entity, String password, List<String> roles, List<String> permissions) {
        this.sub = String.valueOf(entity.getId());
        this.password = password;
        this.enabled = entity.isEnabled();
        this.accountNonLocked = entity.isAccountNonLocked();
        this.authorities = List.of();
        this.roles = roles == null ? List.of() : List.copyOf(roles);
        this.permissions = permissions == null ? List.of() : List.copyOf(permissions);
    }

    /** 본사 토큰에 넣을 역할과 권한. tenant_id 는 없다. */
    public AccessTokenClaims accessTokenClaims() {
        return new AccessTokenClaims(roles, permissions, null);
    }

    /** 회원 번호 문자열. 이메일이 아니다. */
    @Override
    public @NonNull String getUsername() {
        return sub;
    }

    /** 로그인 인증에는 쓰지 않는다. 역할 코드는 accessTokenClaims 에 있다. */
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