package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.dao.BrowserSessionDAO;
import com.goodlifecoder.groupware.security.dao.RefreshTokenDAO;
import com.goodlifecoder.groupware.security.jwt.AccessTokenProvider;
import com.goodlifecoder.groupware.security.session.BrowserSession;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceRevokeTest {

    private final RefreshTokenDAO refreshTokenDAO = mock(RefreshTokenDAO.class);
    private final BrowserSessionDAO browserSessionDAO = mock(BrowserSessionDAO.class);
    private final AuthService authService = new AuthService(
            mock(AccessTokenProvider.class),
            refreshTokenDAO,
            browserSessionDAO,
            mock(CustomUserDetailsService.class),
            new com.goodlifecoder.groupware.security.config.AuthProperties(
                    null, null, null, null, Duration.ofMinutes(15), Duration.ofDays(7), Duration.ofSeconds(15)
            )
    );

    @Test
    void revokeUserClosesIndexedSessionsAndTheCurrentSession() {
        when(browserSessionDAO.sessionIds("7")).thenReturn(Set.of("other-device"));
        when(browserSessionDAO.find("other-device")).thenReturn(Optional.of(session("refresh-other")));
        when(browserSessionDAO.find("current")).thenReturn(Optional.of(session("refresh-current")));

        authService.revokeUser("7", "current");

        verify(refreshTokenDAO).deleteTokenHash("refresh-other");
        verify(refreshTokenDAO).deleteTokenHash("refresh-current");
        verify(browserSessionDAO).delete("other-device");
        verify(browserSessionDAO).delete("current");
        verify(browserSessionDAO).clearSessionIndex("7");
    }

    private static BrowserSession session(String refreshToken) {
        return new BrowserSession("7", refreshToken, "access", 1L);
    }
}
