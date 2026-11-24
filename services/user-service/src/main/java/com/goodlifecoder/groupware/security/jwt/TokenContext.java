package com.goodlifecoder.groupware.security.jwt;

/**
 * 액세스 토큰의 context. 게이트웨이가 경로를 구분할 때 쓴다.
 */
public enum TokenContext {
    ACCOUNT("account"),
    PLATFORM("platform"),
    TENANT("tenant");

    private final String claim;

    TokenContext(String claim) {
        this.claim = claim;
    }

    /** JWT context 클레임 값. */
    public String claim() {
        return claim;
    }
}
