package com.goodlifecoder.groupware.security.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.goodlifecoder.groupware.security.config.AuthProperties;
import com.goodlifecoder.groupware.security.dao.BrowserSessionDAO;
import com.goodlifecoder.groupware.security.dao.RefreshTokenDAO;
import com.goodlifecoder.groupware.security.entity.CustomUserDetails;
import com.goodlifecoder.groupware.security.jwt.AccessTokenClaims;
import com.goodlifecoder.groupware.security.jwt.AccessTokenProvider;
import com.goodlifecoder.groupware.security.jwt.TokenContext;
import com.goodlifecoder.groupware.security.session.BrowserSession;
import com.goodlifecoder.groupware.security.session.LoginEntrance;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AuthServiceLoginTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID TENANT_ID = UUID.fromString("00000000-0000-0000-0000-000000000010");
    private static final String SUB = USER_ID.toString();

    private final AccessTokenProvider tokens = mock(AccessTokenProvider.class);
    private final RefreshTokenDAO refreshTokens = mock(RefreshTokenDAO.class);
    private final BrowserSessionDAO sessions = mock(BrowserSessionDAO.class);
    private final CustomUserDetailsService userDetails = mock(CustomUserDetailsService.class);
    private final LoginTokenService loginTokens = mock(LoginTokenService.class);
    private final AuthService authService = new AuthService(
            tokens,
            refreshTokens,
            sessions,
            userDetails,
            loginTokens,
            new AuthProperties(null, null, null, "user-service", Duration.ofMinutes(15), Duration.ofDays(7), Duration.ofSeconds(15))
    );

    @BeforeEach
    void issueTokens() {
        when(refreshTokens.generateAndSave(SUB)).thenReturn("refresh");
        when(tokens.issueAccessToken(eq(SUB), any())).thenReturn("access");
        when(sessions.saveNew(any())).thenReturn("sid");
    }

    @Test
    void platformLoginIssuesHeadquartersClaimsOnly() {
        when(userDetails.loadUserById(SUB)).thenReturn(details());
        when(userDetails.platformClaims(USER_ID)).thenReturn(headquartersClaims());

        assertThat(authService.openPlatformSession(SUB)).contains("sid");

        BrowserSession saved = savedSession();
        assertThat(saved.entrance()).isEqualTo(LoginEntrance.PLATFORM);
        assertThat(saved.tenantId()).isNull();
        assertThat(issuedClaims().tenantId()).isNull();
        assertThat(issuedClaims().context()).isEqualTo(TokenContext.PLATFORM);
        assertThat(issuedClaims().permissions()).containsExactly("user:read");
        verify(loginTokens, never()).tenantClaims(any(), any(String.class));
        verify(userDetails).platformClaims(USER_ID);
    }

    @Test
    void platformLoginWithoutAHeadquartersRoleDoesNotOpenASession() {
        when(userDetails.loadUserById(SUB)).thenReturn(details());
        when(userDetails.platformClaims(USER_ID)).thenReturn(AccessTokenClaims.account());

        assertThat(authService.openPlatformSession(SUB)).isEmpty();

        verify(sessions, never()).saveNew(any());
        verify(tokens, never()).issueAccessToken(any(), any());
        verify(userDetails).platformClaims(USER_ID);
    }

    @Test
    void memberLoginDiscardsThePreviousBrowserSession() {
        when(userDetails.loadUserById(SUB)).thenReturn(details());
        when(sessions.find("old")).thenReturn(Optional.of(expired(LoginEntrance.TENANT, TENANT_ID)));

        assertThat(authService.openSession(SUB, "old")).isEqualTo("sid");

        verify(refreshTokens).deleteTokenHash("old-refresh");
        verify(sessions).delete("old");
        assertThat(issuedClaims().context()).isEqualTo(TokenContext.ACCOUNT);
        assertThat(issuedClaims().permissions()).isEmpty();
        verify(userDetails, never()).platformClaims(any());
    }

    @Test
    void platformLoginDiscardsThePreviousSessionOnlyWhenAHeadquartersRoleExists() {
        when(userDetails.loadUserById(SUB)).thenReturn(details());
        when(userDetails.platformClaims(USER_ID)).thenReturn(AccessTokenClaims.account());

        assertThat(authService.openPlatformSession(SUB, "old")).isEmpty();

        verify(sessions, never()).delete(any());
        verify(userDetails).platformClaims(USER_ID);
    }

    @Test
    void leaveTenantReplacesTheSessionWithAnAccountToken() {
        when(sessions.find("sid")).thenReturn(Optional.of(expired(LoginEntrance.TENANT, TENANT_ID)));
        when(userDetails.loadUserById(SUB)).thenReturn(details());

        assertThat(authService.leaveTenant("sid")).contains(true);

        verify(refreshTokens).deleteTokenHash("old-refresh");
        BrowserSession saved = replacedSession();
        assertThat(saved.entrance()).isNull();
        assertThat(saved.tenantId()).isNull();
        assertThat(issuedClaims().context()).isEqualTo(TokenContext.ACCOUNT);
        assertThat(issuedClaims().permissions()).isEmpty();
        verify(userDetails, never()).platformClaims(any());
    }

    @Test
    void leaveTenantOutsideACompanyDoesNotChangeTheSession() {
        when(sessions.find("sid")).thenReturn(Optional.of(expired(LoginEntrance.PLATFORM, null)));

        assertThat(authService.leaveTenant("sid")).contains(false);

        verify(sessions, never()).save(eq("sid"), any());
        verify(tokens, never()).issueAccessToken(any(), any());
        verify(userDetails, never()).platformClaims(any());
    }

    @Test
    void memberLoginIssuesAnEmptyToken() {
        when(userDetails.loadUserById(SUB)).thenReturn(details());

        assertThat(authService.openSession(SUB)).isEqualTo("sid");

        BrowserSession saved = savedSession();
        assertThat(saved.entrance()).isNull();
        assertThat(saved.tenantId()).isNull();
        assertThat(issuedClaims().context()).isEqualTo(TokenContext.ACCOUNT);
        assertThat(issuedClaims().permissions()).isEmpty();
        assertThat(issuedClaims().tenantId()).isNull();
        verify(userDetails, never()).platformClaims(any());
    }

    @Test
    void tenantEntryReplacesTheSessionWithThatTenantToken() {
        when(sessions.find("sid")).thenReturn(Optional.of(expired(null, null)));
        when(userDetails.loadUserById(SUB)).thenReturn(details());
        when(loginTokens.tenantClaims(USER_ID, "acme")).thenReturn(Optional.of(tenantClaims()));

        assertThat(authService.enterTenant("sid", "acme")).contains(true);

        verify(refreshTokens).deleteTokenHash("old-refresh");
        BrowserSession saved = replacedSession();
        assertThat(saved.entrance()).isEqualTo(LoginEntrance.TENANT);
        assertThat(saved.tenantId()).isEqualTo(TENANT_ID);
        assertThat(issuedClaims()).isEqualTo(tenantClaims());
        verify(userDetails, never()).platformClaims(any());
    }

    @Test
    void tenantEntryFromAHeadquartersSessionDropsHeadquartersPermissions() {
        when(sessions.find("sid")).thenReturn(Optional.of(expired(LoginEntrance.PLATFORM, null)));
        when(userDetails.loadUserById(SUB)).thenReturn(details());
        when(loginTokens.tenantClaims(USER_ID, "acme")).thenReturn(Optional.of(tenantClaims()));

        assertThat(authService.enterTenant("sid", "acme")).contains(true);

        assertThat(replacedSession().entrance()).isEqualTo(LoginEntrance.TENANT);
        assertThat(issuedClaims().permissions()).containsExactly("payroll:read");
        assertThat(issuedClaims().tenantId()).isEqualTo(TENANT_ID);
        verify(userDetails, never()).platformClaims(any());
    }

    @Test
    void tenantEntryWithoutAMembershipLeavesTheSession() {
        when(sessions.find("sid")).thenReturn(Optional.of(expired(null, null)));
        when(userDetails.loadUserById(SUB)).thenReturn(details());
        when(loginTokens.tenantClaims(USER_ID, "missing")).thenReturn(Optional.empty());

        assertThat(authService.enterTenant("sid", "missing")).contains(false);

        verify(sessions, never()).save(org.mockito.ArgumentMatchers.eq("sid"), any());
        verify(refreshTokens, never()).deleteTokenHash(any());
        verify(userDetails, never()).platformClaims(any());
    }

    @Test
    void tenantEntryWithoutASessionIsEmpty() {
        when(sessions.find("sid")).thenReturn(Optional.empty());

        assertThat(authService.enterTenant("sid", "acme")).isEmpty();

        verify(userDetails, never()).platformClaims(any());
    }

    @Test
    void socialLoginDoesNotIssueAHeadquartersToken() {
        when(userDetails.loadUserById(SUB)).thenReturn(details());

        assertThat(authService.openSession(SUB)).isEqualTo("sid");

        BrowserSession saved = savedSession();
        assertThat(saved.entrance()).isNull();
        assertThat(saved.tenantId()).isNull();
        assertThat(issuedClaims().context()).isEqualTo(TokenContext.ACCOUNT);
        assertThat(issuedClaims().permissions()).isEmpty();
        assertThat(issuedClaims().tenantId()).isNull();
        verify(loginTokens, never()).tenantClaims(any(), any(String.class));
        verify(userDetails, never()).platformClaims(any());
    }

    @Test
    void platformRefreshKeepsHeadquartersClaims() {
        when(sessions.find("sid")).thenReturn(Optional.of(expired(LoginEntrance.PLATFORM, null)));
        when(refreshTokens.findAndDelete("old-refresh")).thenReturn(Optional.of(SUB));
        when(userDetails.loadUserById(SUB)).thenReturn(details());
        when(userDetails.platformClaims(USER_ID)).thenReturn(headquartersClaims());

        assertThat(authService.currentAccessToken("sid")).contains("access");

        BrowserSession saved = replacedSession();
        assertThat(saved.entrance()).isEqualTo(LoginEntrance.PLATFORM);
        assertThat(saved.tenantId()).isNull();
        assertThat(issuedClaims().context()).isEqualTo(TokenContext.PLATFORM);
        assertThat(issuedClaims().permissions()).containsExactly("user:read");
        verify(userDetails).platformClaims(USER_ID);
    }

    @Test
    void platformRefreshClosesTheSessionWhenTheHeadquartersRoleIsGone() {
        when(sessions.find("sid")).thenReturn(Optional.of(expired(LoginEntrance.PLATFORM, null)));
        when(refreshTokens.findAndDelete("old-refresh")).thenReturn(Optional.of(SUB));
        when(userDetails.loadUserById(SUB)).thenReturn(details());
        when(userDetails.platformClaims(USER_ID)).thenReturn(AccessTokenClaims.account());

        assertThat(authService.currentAccessToken("sid")).isEmpty();

        verify(sessions).delete("sid");
        verify(tokens, never()).issueAccessToken(any(), any());
        verify(userDetails).platformClaims(USER_ID);
    }

    @Test
    void tenantRefreshDoesNotFallBackToHeadquartersClaims() {
        when(sessions.find("sid")).thenReturn(Optional.of(expired(LoginEntrance.TENANT, TENANT_ID)));
        when(refreshTokens.findAndDelete("old-refresh")).thenReturn(Optional.of(SUB));
        when(userDetails.loadUserById(SUB)).thenReturn(details());
        when(loginTokens.tenantClaims(USER_ID, TENANT_ID)).thenReturn(Optional.of(tenantClaims()));

        assertThat(authService.currentAccessToken("sid")).contains("access");

        BrowserSession saved = replacedSession();
        assertThat(saved.entrance()).isEqualTo(LoginEntrance.TENANT);
        assertThat(saved.tenantId()).isEqualTo(TENANT_ID);
        assertThat(issuedClaims()).isEqualTo(tenantClaims());
        verify(userDetails, never()).platformClaims(any());
    }

    @Test
    void tenantRefreshClosesTheSessionWhenTheMembershipIsGone() {
        when(sessions.find("sid")).thenReturn(Optional.of(expired(LoginEntrance.TENANT, TENANT_ID)));
        when(refreshTokens.findAndDelete("old-refresh")).thenReturn(Optional.of(SUB));
        when(userDetails.loadUserById(SUB)).thenReturn(details());
        when(loginTokens.tenantClaims(USER_ID, TENANT_ID)).thenReturn(Optional.empty());

        assertThat(authService.currentAccessToken("sid")).isEmpty();

        verify(sessions).delete("sid");
        verify(tokens, never()).issueAccessToken(any(), any());
        verify(userDetails, never()).platformClaims(any());
    }

    @Test
    void socialRefreshStaysEmptyEvenWhenTheAccountHasHeadquartersRoles() {
        when(sessions.find("sid")).thenReturn(Optional.of(expired(null, null)));
        when(refreshTokens.findAndDelete("old-refresh")).thenReturn(Optional.of(SUB));
        when(userDetails.loadUserById(SUB)).thenReturn(details());

        assertThat(authService.currentAccessToken("sid")).contains("access");

        BrowserSession saved = replacedSession();
        assertThat(saved.entrance()).isNull();
        assertThat(saved.tenantId()).isNull();
        assertThat(issuedClaims().context()).isEqualTo(TokenContext.ACCOUNT);
        assertThat(issuedClaims().permissions()).isEmpty();
        verify(userDetails, never()).platformClaims(any());
    }

    private BrowserSession savedSession() {
        ArgumentCaptor<BrowserSession> captor = ArgumentCaptor.forClass(BrowserSession.class);
        verify(sessions).saveNew(captor.capture());
        return captor.getValue();
    }

    private BrowserSession replacedSession() {
        ArgumentCaptor<BrowserSession> captor = ArgumentCaptor.forClass(BrowserSession.class);
        verify(sessions).save(eq("sid"), captor.capture());
        return captor.getValue();
    }

    private AccessTokenClaims issuedClaims() {
        ArgumentCaptor<AccessTokenClaims> captor = ArgumentCaptor.forClass(AccessTokenClaims.class);
        verify(tokens).issueAccessToken(eq(SUB), captor.capture());
        return captor.getValue();
    }

    private static CustomUserDetails details() {
        UserEntity user = UserEntity.builder()
                .id(USER_ID)
                .enabled(true)
                .accountNonLocked(true)
                .build();
        return new CustomUserDetails(user, "{noop}secret");
    }

    private static AccessTokenClaims headquartersClaims() {
        return new AccessTokenClaims(TokenContext.PLATFORM, List.of("user:read"), null);
    }

    private static AccessTokenClaims tenantClaims() {
        return new AccessTokenClaims(TokenContext.TENANT, List.of("payroll:read"), TENANT_ID);
    }

    private static BrowserSession expired(LoginEntrance entrance, UUID tenantId) {
        return new BrowserSession(SUB, "old-refresh", "old-access", 1L, entrance, tenantId);
    }
}
