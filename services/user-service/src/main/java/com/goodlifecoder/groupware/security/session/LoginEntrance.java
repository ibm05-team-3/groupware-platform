package com.goodlifecoder.groupware.security.session;

/**
 * 세션을 연 로그인 입구. 갱신할 때도 이 입구의 토큰만 다시 발급한다.
 */
public enum LoginEntrance {
    PLATFORM,
    TENANT
}
