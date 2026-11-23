package com.goodlifecoder.groupware.security.oauth;

import com.goodlifecoder.groupware.security.session.LoginEntrance;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * 본사 소셜 로그인 표시. 인가 요청에 실었다가 콜백 요청으로 옮긴다.
 * 회원 소셜에는 이 속성을 넣지 않는다.
 */
public final class LoginEntranceOAuth {

    public static final String ATTRIBUTE = "login_entrance";

    private LoginEntranceOAuth() {
    }

    /** 본사 입구 표시를 붙인다. authorizationRequestUri 는 유지한다. */
    public static OAuth2AuthorizationRequest tagPlatform(OAuth2AuthorizationRequest authorizationRequest) {
        if (authorizationRequest == null) {
            return null;
        }
        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .authorizationRequestUri(authorizationRequest.getAuthorizationRequestUri())
                .attributes(attributes -> attributes.put(ATTRIBUTE, LoginEntrance.PLATFORM.name()))
                .build();
    }

    /** 인가 요청의 본사 입구 표시를 콜백 요청 속성으로 옮긴다. */
    public static void remember(HttpServletRequest request, OAuth2AuthorizationRequest authorizationRequest) {
        if (LoginEntrance.PLATFORM.name().equals(authorizationRequest.getAttribute(ATTRIBUTE))) {
            request.setAttribute(ATTRIBUTE, LoginEntrance.PLATFORM.name());
        }
    }

    /** 이 콜백이 본사 소셜 로그인인지. */
    public static boolean platform(HttpServletRequest request) {
        return LoginEntrance.PLATFORM.name().equals(request.getAttribute(ATTRIBUTE));
    }
}
