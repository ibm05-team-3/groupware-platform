package com.goodlifecoder.groupware.security.oauth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 루트 가입 소셜 연결. 확인된 가입 토큰을 인가 요청에 실었다가 콜백 요청으로 옮긴다.
 */
public final class RootSignupOAuth {

    public static final String PARAMETER = "root_signup_token";

    private RootSignupOAuth() {
    }

    /** 쿼리의 가입 토큰을 인가 요청 속성으로 넣는다. 없으면 요청을 그대로 둔다. */
    public static OAuth2AuthorizationRequest attach(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request) {
        if (authorizationRequest == null) {
            return null;
        }
        String token = request.getParameter(PARAMETER);
        if (token == null || token.isBlank()) {
            return authorizationRequest;
        }
        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .authorizationRequestUri(authorizationRequest.getAuthorizationRequestUri())
                .attributes(attributes -> attributes.put(PARAMETER, token))
                .build();
    }

    /** 인가 요청의 가입 토큰을 콜백 요청 속성으로 옮긴다. */
    public static void remember(HttpServletRequest request, OAuth2AuthorizationRequest authorizationRequest) {
        Object value = authorizationRequest.getAttribute(PARAMETER);
        if (value instanceof String token && !token.isBlank()) {
            request.setAttribute(PARAMETER, token);
        }
    }

    /** 지금 요청에 실린 가입 토큰. 없으면 비운다. */
    public static String currentToken() {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) {
            return null;
        }
        Object value = attributes.getRequest().getAttribute(PARAMETER);
        if (value instanceof String token && !token.isBlank()) {
            return token;
        }
        return null;
    }
}
