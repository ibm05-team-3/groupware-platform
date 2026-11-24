package com.goodlifecoder.groupware.security.dao;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * 루트 가입 대기. 확인 전에는 이메일만 7일 보관하고 비밀번호는 두지 않는다.
 * 코드를 맞추면 30분짜리 가입 토큰으로 바뀐다. 회원 행은 만들지 않는다.
 */
@Component
@RequiredArgsConstructor
public class RootSignupStore {

    public static final Duration VERIFIED_TTL = Duration.ofMinutes(30);
    private static final String PENDING_PREFIX = "auth:root-signup-pending:";
    private static final String VERIFIED_PREFIX = "auth:root-signup-verified:";

    private final StringRedisTemplate redis;

    /** 이메일을 남은 시간만큼 저장한다. 시간이 없으면 지운다. */
    public void savePending(String email, Duration ttl) {
        if (ttl == null || ttl.isZero() || ttl.isNegative() || email == null || email.isBlank()) {
            deletePending(email);
            return;
        }
        Duration kept = ttl.truncatedTo(ChronoUnit.SECONDS);
        if (kept.isZero()) {
            kept = Duration.ofSeconds(1);
        }
        redis.opsForValue().set(pendingKey(email), email, kept);
    }

    /** 남은 보관 시간. 없거나 만료면 비운다. */
    public Optional<Duration> remaining(String email) {
        Long seconds = redis.getExpire(pendingKey(email), TimeUnit.SECONDS);
        if (seconds == null || seconds <= 0) {
            return Optional.empty();
        }
        return Optional.of(Duration.ofSeconds(seconds));
    }

    /** 이메일로 대기를 읽는다. */
    public Optional<String> findPending(String email) {
        return optionalText(redis.opsForValue().get(pendingKey(email)));
    }

    /** 그 이메일의 대기를 지운다. */
    public void deletePending(String email) {
        if (email == null || email.isBlank()) {
            return;
        }
        redis.delete(pendingKey(email));
    }

    /** 확인된 이메일의 짧은 가입 토큰. 30분이고 아직 로그인할 수 없다. */
    public String issueVerified(String email) {
        String raw = RefreshTokenDAO.generateOpaqueRefreshToken();
        redis.opsForValue().set(VERIFIED_PREFIX + RefreshTokenDAO.hash(raw), email, VERIFIED_TTL);
        return raw;
    }

    /** 짧은 가입 토큰의 이메일. 없거나 만료면 비운다. */
    public Optional<String> findVerified(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }
        return optionalText(redis.opsForValue().get(VERIFIED_PREFIX + RefreshTokenDAO.hash(rawToken)));
    }

    /** 짧은 가입 토큰을 지운다. */
    public void deleteVerified(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return;
        }
        redis.delete(VERIFIED_PREFIX + RefreshTokenDAO.hash(rawToken));
    }

    private static String pendingKey(String email) {
        return PENDING_PREFIX + RefreshTokenDAO.hash(email);
    }

    private static Optional<String> optionalText(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(value);
    }
}
