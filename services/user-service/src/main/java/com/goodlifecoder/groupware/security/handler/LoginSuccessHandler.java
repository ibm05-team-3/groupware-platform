package com.goodlifecoder.groupware.security.handler;

import com.goodlifecoder.groupware.security.dto.SessionResponseDTO;
import com.goodlifecoder.groupware.security.filter.LoginFilter;
import com.goodlifecoder.groupware.security.http.SessionCookieFactory;
import com.goodlifecoder.groupware.security.service.AuthService;
import com.goodlifecoder.groupware.security.session.LoginEntrance;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 이메일 로그인 성공. 세션 쿠키를 심고 토큰 없는 JSON 을 돌려준다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@RequiredArgsConstructor
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final AuthService authService;
    private final SessionCookieFactory sessionCookieFactory;
    private final LoginEntrance entrance;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /** 세션을 열고 Set-Cookie 와 SessionResponseDTO 를 쓴다. */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        // authentication.getName() => CustomUserDetails 의 getName 과 동일한 값
        String sub = authentication.getName();
        String sessionId = entrance == LoginEntrance.PLATFORM
                ? authService.openPlatformSession(sub).orElse(null)
                : authService.openTenantSession(sub, String.valueOf(request.getAttribute(LoginFilter.TENANT_SLUG))).orElse(null);
        if (sessionId == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        response.addHeader(HttpHeaders.SET_COOKIE, sessionCookieFactory.write(sessionId).toString());
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getWriter(), new SessionResponseDTO(true, sub, null));
    }
}
