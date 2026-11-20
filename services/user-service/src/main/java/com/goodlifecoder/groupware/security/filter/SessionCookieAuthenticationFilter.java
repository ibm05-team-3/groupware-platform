package com.goodlifecoder.groupware.security.filter;

import com.goodlifecoder.groupware.security.http.CurrentSessionUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 세션 쿠키가 있으면 그 요청을 인증된 것으로 둔다. 공개 주소가 아닌 API는 이 인증이 있어야 한다.
 */
public class SessionCookieAuthenticationFilter extends OncePerRequestFilter {

    private final CurrentSessionUser currentSessionUser;

    public SessionCookieAuthenticationFilter(CurrentSessionUser currentSessionUser) {
        this.currentSessionUser = currentSessionUser;
    }

    /** 아직 인증이 없고 쿠키로 회원 번호를 읽으면 SecurityContext 에 넣는다. */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            currentSessionUser.id(request).ifPresent(userId -> {
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userId, null, List.of());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            });
        }
        chain.doFilter(request, response);
    }
}
