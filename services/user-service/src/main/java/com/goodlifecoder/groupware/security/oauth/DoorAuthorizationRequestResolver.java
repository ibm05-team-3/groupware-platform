package com.goodlifecoder.groupware.security.oauth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * 회원 소셜과 본사 소셜의 시작 주소를 나눈다.
 * 콜백 주소는 회원 소셜과 같다. 본사 여부는 인가 요청에 남긴다.
 */
public final class DoorAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    static final String PLATFORM_AUTHORIZATION_BASE = "/platform/oauth2/authorization";

    private final OAuth2AuthorizationRequestResolver member;
    private final OAuth2AuthorizationRequestResolver platform;

    /** 회원 해석기와 본사 해석기. 본사 경로는 본사 해석기만 쓴다. */
    public DoorAuthorizationRequestResolver(
            OAuth2AuthorizationRequestResolver member,
            OAuth2AuthorizationRequestResolver platform
    ) {
        this.member = member;
        this.platform = platform;
    }

    /** 시작 경로에 맞는 인가 요청. 본사면 입구 표시를 붙인다. */
    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        if (platformStart(request)) {
            return LoginEntranceOAuth.tagPlatform(platform.resolve(request));
        }
        return member.resolve(request);
    }

    /** 등록 id 로 해석한다. 본사 경로는 회원 해석기로 넘어가지 않는다. */
    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        if (platformStart(request)) {
            return LoginEntranceOAuth.tagPlatform(platform.resolve(request, clientRegistrationId));
        }
        return member.resolve(request, clientRegistrationId);
    }

    /** 컨텍스트 경로를 뺀 주소가 본사 소셜 시작인지. */
    private static boolean platformStart(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String context = request.getContextPath() == null ? "" : request.getContextPath();
        String path = uri.startsWith(context) ? uri.substring(context.length()) : uri;
        return path.equals(PLATFORM_AUTHORIZATION_BASE) || path.startsWith(PLATFORM_AUTHORIZATION_BASE + "/");
    }
}
