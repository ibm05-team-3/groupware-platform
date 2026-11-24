package com.goodlifecoder.groupware.security.jwt;

/**
 * 액세스 토큰의 context. 게이트웨이는 platform 일 때만 본사 경로에 쓴다.
 */
public enum TokenContext {
    TENANT("tenant"),
    ACCOUNT("account"),
    PLATFORM("platform");

    private final String claim;

    TokenContext(String claim) {
        this.claim = claim;
    }

    /** JWT context 클레임 값. */
    public String claim() {
        return claim;
    }
}
