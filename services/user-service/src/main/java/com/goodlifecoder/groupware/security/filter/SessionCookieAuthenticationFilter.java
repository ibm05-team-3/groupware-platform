package com.goodlifecoder.groupware.security.filter;

import com.goodlifecoder.groupware.iam.repository.UserPlatformRoleRepository;
import com.goodlifecoder.groupware.security.http.CurrentSessionUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 세션 쿠키가 있으면 그 요청을 인증된 것으로 둔다. 공개 주소가 아닌 API는 이 인증이 있어야 한다.
 * 본사 역할이 있으면 SCOPE_PLATFORM 을 붙인다. 게이트웨이를 거치지 않은 요청도 이 권한으로 가른다.
 */
public class SessionCookieAuthenticationFilter extends OncePerRequestFilter {

    public static final String PLATFORM_AUTHORITY = "SCOPE_PLATFORM";

    private final CurrentSessionUser currentSessionUser;
    private final UserPlatformRoleRepository platformRoles;

    public SessionCookieAuthenticationFilter(
            CurrentSessionUser currentSessionUser,
            UserPlatformRoleRepository platformRoles) {
        this.currentSessionUser = currentSessionUser;
        this.platformRoles = platformRoles;
    }

    /** 아직 인증이 없고 쿠키로 회원 번호를 읽으면 SecurityContext 에 넣는다. */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            currentSessionUser.id(request).ifPresent(userId -> {
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userId, null, authoritiesOf(userId));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            });
        }
        chain.doFilter(request, response);
    }

    /** 본사 역할이 있는 회원만 SCOPE_PLATFORM 을 가진다. */
    private List<SimpleGrantedAuthority> authoritiesOf(UUID userId) {
        if (!platformRoles.existsByIdUserId(userId)) {
            return List.of();
        }
        return List.of(new SimpleGrantedAuthority(PLATFORM_AUTHORITY));
    }
}
