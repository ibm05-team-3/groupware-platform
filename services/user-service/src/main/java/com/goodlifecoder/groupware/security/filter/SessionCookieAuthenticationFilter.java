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
 * 본사 역할 조회는 /platform/** 에서만 하고, 있으면 SCOPE_PLATFORM 을 붙인다.
 * 게이트웨이를 거치지 않은 요청도 이 권한으로 가른다.
 * /internal/session/access 는 컨트롤러가 쿠키를 직접 읽으므로 이 필터를 타지 않는다.
 */
public class SessionCookieAuthenticationFilter extends OncePerRequestFilter {

    public static final String PLATFORM_AUTHORITY = "SCOPE_PLATFORM";
    private static final String INTERNAL_ACCESS_PATH = "/internal/session/access";
    private static final String PLATFORM_PATH = "/platform";

    private final CurrentSessionUser currentSessionUser;
    private final UserPlatformRoleRepository platformRoles;

    public SessionCookieAuthenticationFilter(
            CurrentSessionUser currentSessionUser,
            UserPlatformRoleRepository platformRoles) {
        this.currentSessionUser = currentSessionUser;
        this.platformRoles = platformRoles;
    }

    /** 액세스 토큰 교환은 권한을 쓰지 않으므로 세션과 본사 역할을 읽지 않는다. */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return INTERNAL_ACCESS_PATH.equals(path(request));
    }

    /** 아직 인증이 없고 쿠키로 회원 번호를 읽으면 SecurityContext 에 넣는다. */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            currentSessionUser.id(request).ifPresent(userId -> {
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userId, null, authoritiesOf(request, userId));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            });
        }
        chain.doFilter(request, response);
    }

    /** 본사 화면이 아니면 역할을 조회하지 않는다. 역할이 있는 회원만 SCOPE_PLATFORM 을 가진다. */
    private List<SimpleGrantedAuthority> authoritiesOf(HttpServletRequest request, UUID userId) {
        if (!platformPath(request) || !platformRoles.existsByIdUserId(userId)) {
            return List.of();
        }
        return List.of(new SimpleGrantedAuthority(PLATFORM_AUTHORITY));
    }

    /** /platform 과 그 하위 주소만 본사 역할이 필요하다. */
    private static boolean platformPath(HttpServletRequest request) {
        String path = path(request);
        return PLATFORM_PATH.equals(path) || path.startsWith(PLATFORM_PATH + "/");
    }

    /** 컨텍스트 경로를 뺀 요청 경로. */
    private static String path(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        if (context != null && !context.isEmpty() && uri.startsWith(context)) {
            return uri.substring(context.length());
        }
        return uri;
    }
}
