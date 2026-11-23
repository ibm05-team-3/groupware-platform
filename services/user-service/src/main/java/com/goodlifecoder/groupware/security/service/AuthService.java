package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.config.AuthProperties;
import com.goodlifecoder.groupware.security.jwt.AccessTokenClaims;
import com.goodlifecoder.groupware.security.dao.BrowserSessionDAO;
import com.goodlifecoder.groupware.security.dao.RefreshTokenDAO;
import com.goodlifecoder.groupware.security.entity.CustomUserDetails;
import com.goodlifecoder.groupware.security.jwt.AccessTokenProvider;
import com.goodlifecoder.groupware.security.session.BrowserSession;
import com.goodlifecoder.groupware.security.session.LoginEntrance;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * 브라우저 세션의 발급, 조회, 액세스 토큰 갱신, 로그아웃, 회원 단위 폐기.
 * 쿠키 값은 세션 번호이고, 액세스·리프레시 토큰은 Redis 에만 둔다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@Service
@RequiredArgsConstructor
public class AuthService {
    private final AccessTokenProvider accessTokenProvider;
    private final RefreshTokenDAO refreshTokenDAO;
    private final BrowserSessionDAO browserSessionDAO;
    private final CustomUserDetailsService userDetailsService;
    private final LoginTokenService loginTokens;
    private final AuthProperties authProperties;

    private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    /** 회원 소셜 로그인 세션. 본사 역할이 있어도 본사 토큰을 발급하지 않는다. */
    public String openSession(String accessSub) {
        findAndValidateUser(accessSub);
        return browserSessionDAO.saveNew(issue(accessSub, new AccessTokenClaims(List.of(), List.of(), null), null));
    }

    /** 본사 이메일 로그인. 본사 역할이 없으면 세션을 열지 않는다. */
    public Optional<String> openPlatformSession(String accessSub) {
        UserDetails userDetails = findAndValidateUser(accessSub);
        AccessTokenClaims claims = claimsOf(userDetails);
        if (claims.roles().isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(browserSessionDAO.saveNew(issue(accessSub, claims, LoginEntrance.PLATFORM)));
    }

    /**
     * 로그인된 세션을 그 회사 토큰으로 바꾼다.
     * 세션이 없으면 empty, 활성 소속이 없으면 false, 바꾸면 true.
     * 본사 권한이 있던 세션이어도 회사 권한만 남긴다.
     */
    public Optional<Boolean> enterTenant(String sessionId, String slug) {
        Optional<BrowserSession> stored = browserSessionDAO.find(sessionId);
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        BrowserSession session = stored.get();
        findAndValidateUser(session.sub());
        Optional<AccessTokenClaims> claims = loginTokens.tenantClaims(userId(session.sub()), slug);
        if (claims.isEmpty()) {
            return Optional.of(false);
        }
        refreshTokenDAO.deleteTokenHash(session.refreshToken());
        browserSessionDAO.save(sessionId, issue(session.sub(), claims.get(), LoginEntrance.TENANT));
        return Optional.of(true);
    }

    /** 그 테넌트 토큰으로 새 세션을 연다. 소속이 없으면 비운다. */
    public Optional<String> openTenantSession(String accessSub, String tenantSlug) {
        findAndValidateUser(accessSub);
        Optional<AccessTokenClaims> claims = loginTokens.tenantClaims(userId(accessSub), tenantSlug);
        return claims.map(value -> browserSessionDAO.saveNew(issue(accessSub, value, LoginEntrance.TENANT)));
    }

    /** 세션의 회원 번호. 세션이 없으면 비운다. */
    public Optional<String> sessionSubject(String sessionId) {
        return browserSessionDAO.find(sessionId).map(BrowserSession::sub);
    }

    /**
     * 아직 갱신 여유 밖이면 저장된 액세스 토큰을 그대로 돌려준다.
     * 여유 안이면 리프레시 토큰을 소비하고 액세스 토큰만 다시 발급해 같은 세션에 덮어쓴다.
     */
    public Optional<String> currentAccessToken(String sessionId) {
        Optional<BrowserSession> stored = browserSessionDAO.find(sessionId);
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        BrowserSession session = stored.get();
        if (accessStillValid(session)) {
            return Optional.of(session.accessToken());
        }

        Optional<String> rotatedSub = refreshTokenDAO.findAndDelete(session.refreshToken());
        if (rotatedSub.isEmpty()) {
            return browserSessionDAO.find(sessionId)
                    .filter(latest -> latest.accessExpiresAtEpochMilli() > Instant.now().toEpochMilli())
                    .map(BrowserSession::accessToken);
        }
        if (!rotatedSub.get().equals(session.sub())) {
            browserSessionDAO.delete(sessionId);
            return Optional.empty();
        }

        Optional<BrowserSession> renewed = renew(rotatedSub.get(), session);
        if (renewed.isEmpty()) {
            browserSessionDAO.delete(sessionId);
            return Optional.empty();
        }
        browserSessionDAO.save(sessionId, renewed.get());
        return Optional.of(renewed.get().accessToken());
    }

    /** 이 세션과 그 리프레시 토큰만 지운다. */
    public void closeSession(String sessionId) {
        browserSessionDAO.find(sessionId)
                .ifPresent(session -> refreshTokenDAO.deleteTokenHash(session.refreshToken()));
        browserSessionDAO.delete(sessionId);
    }

    /** 인덱스에 있는 세션과 현재 쿠키 세션을 끊고 회원별 인덱스를 비운다. */
    public void revokeUser(String userId, String currentSessionId) {
        Set<String> sessionIds = new HashSet<>(browserSessionDAO.sessionIds(userId));
        if (currentSessionId != null && !currentSessionId.isBlank()) {
            sessionIds.add(currentSessionId);
        }
        sessionIds.forEach(this::closeSession);
        browserSessionDAO.clearSessionIndex(userId);
    }

    /** 같은 입구의 토큰만 다시 발급한다. 테넌트 소속이 없어지면 본사 토큰으로 바꾸지 않는다. */
    private Optional<BrowserSession> renew(String accessSub, BrowserSession session) {
        if (session.entrance() == LoginEntrance.TENANT) {
            if (session.tenantId() == null) {
                return Optional.empty();
            }
            findAndValidateUser(accessSub);
            return loginTokens.tenantClaims(userId(accessSub), session.tenantId())
                    .map(value -> issue(accessSub, value, LoginEntrance.TENANT));
        }
        if (session.entrance() != LoginEntrance.PLATFORM) {
            findAndValidateUser(accessSub);
            return Optional.of(issue(accessSub, new AccessTokenClaims(List.of(), List.of(), null), null));
        }
        UserDetails userDetails = findAndValidateUser(accessSub);
        AccessTokenClaims claims = claimsOf(userDetails);
        if (claims.roles().isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(issue(accessSub, claims, LoginEntrance.PLATFORM));
    }

    /** 계정을 확인한 뒤 그 입구의 액세스·리프레시 토큰을 발급해 세션 값을 만든다. */
    private BrowserSession issue(String accessSub, AccessTokenClaims claims, LoginEntrance entrance) {
        Instant accessExpiresAt = Instant.now().plus(authProperties.accessTokenExpiration());
        String refreshToken = refreshTokenDAO.generateAndSave(accessSub);
        String accessToken = accessTokenProvider.issueAccessToken(accessSub, claims);
        return new BrowserSession(
                accessSub,
                refreshToken,
                accessToken,
                accessExpiresAt.toEpochMilli(),
                entrance,
                claims.tenantId());
    }

    /** 만료 시각에서 갱신 여유를 뺀 시각이 아직 미래면 true. */
    private boolean accessStillValid(BrowserSession session) {
        return session.accessExpiresAtEpochMilli() - authProperties.accessTokenRefreshSkew().toMillis() > Instant.now().toEpochMilli();
    }

    /** 본사 역할과 권한만 있는 토큰. tenant_id 는 넣지 않는다. */
    private static AccessTokenClaims claimsOf(UserDetails userDetails) {
        if (userDetails instanceof CustomUserDetails details) {
            return details.accessTokenClaims();
        }
        return new AccessTokenClaims(List.of(), List.of(), null);
    }

    /** 회원 번호로 계정을 읽고 잠금·비활성 여부를 확인한다. */
    private UserDetails findAndValidateUser(String accessSub) {
        UserDetails userDetails = userDetailsService.loadUserById(accessSub);
        userDetailsChecker.check(userDetails);
        return userDetails;
    }

    /** 세션 회원 번호는 UUID 문자열이다. */
    private static UUID userId(String accessSub) {
        return UUID.fromString(accessSub);
    }
}
