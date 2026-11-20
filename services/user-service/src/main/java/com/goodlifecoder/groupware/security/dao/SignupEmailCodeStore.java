package com.goodlifecoder.groupware.security.dao;

import java.security.MessageDigest;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * 가입 확인 토큰은 이메일과 묶인 해시만 저장한다. 원문은 메일로만 나간다.
 * 일반 가입과 루트 가입은 키를 나눠, 한쪽 토큰으로 다른 쪽을 확인하지 못한다.
 * 토큰은 32바이트 난수이고 10분이다. 실패는 5회까지고, 그 뒤에는 다시 보낼 때까지 확인을 거절한다.
 * 재발송 간격은 60초다.
 */
@Component
@RequiredArgsConstructor
public class SignupEmailCodeStore {

    public static final Duration TTL = Duration.ofMinutes(10);
    public static final int MAX_ATTEMPTS = 5;
    public static final Duration RESEND = Duration.ofSeconds(60);

    private final StringRedisTemplate redis;

    /** 일반 가입과 루트 가입의 Redis 접두사. */
    public enum Flow {
        SIGNUP("auth:signup-code:"),
        ROOT("auth:root-signup-code:");

        private final String prefix;

        Flow(String prefix) {
            this.prefix = prefix;
        }
    }

    /** 확인 결과. 맞음, 틀림, 시도 초과. */
    public enum Status {
        MATCH,
        WRONG,
        EXHAUSTED
    }

    /** 성공한 발송 뒤 60초가 지나지 않았으면 true. */
    public boolean coolingDown(Flow flow, String email) {
        return Boolean.TRUE.equals(redis.hasKey(cooldownKey(flow, email)));
    }

    /**
     * 32바이트 난수 토큰을 만들고 해시만 저장한다. 이전 토큰과 실패 횟수는 지운다.
     */
    public String issue(Flow flow, String email) {
        String code = RefreshTokenDAO.generateOpaqueRefreshToken();
        redis.delete(attemptsKey(flow, email));
        redis.opsForValue().set(codeKey(flow, email), codeHash(email, code), TTL);
        return code;
    }

    /** 메일을 보낸 뒤에만 60초 재발송 제한을 건다. */
    public void rememberSend(Flow flow, String email) {
        redis.opsForValue().set(cooldownKey(flow, email), "1", RESEND);
    }

    /** 코드, 실패 횟수, 재발송 제한을 지운다. 잠금은 남긴다. */
    public void revoke(Flow flow, String email) {
        redis.delete(codeKey(flow, email));
        redis.delete(attemptsKey(flow, email));
        redis.delete(cooldownKey(flow, email));
    }

    /**
     * 이메일과 토큰을 맞춘다.
     * 이미 5번 틀렸으면 토큰을 비교하지 않고 EXHAUSTED. 토큰은 남겨 둔다.
     * 없거나 다르면 실패로 센다. 5회째도 토큰은 지우지 않고 EXHAUSTED.
     * 맞으면 토큰과 실패 횟수를 지우고 MATCH.
     */
    public Status check(Flow flow, String email, String code) {
        if (attemptsUsed(flow, email) >= MAX_ATTEMPTS) {
            return Status.EXHAUSTED;
        }
        String stored = redis.opsForValue().get(codeKey(flow, email));
        if (stored != null && MessageDigest.isEqual(
                stored.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                codeHash(email, code).getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            redis.delete(codeKey(flow, email));
            redis.delete(attemptsKey(flow, email));
            return Status.MATCH;
        }
        Long count = redis.opsForValue().increment(attemptsKey(flow, email));
        redis.expire(attemptsKey(flow, email), TTL);
        if (count != null && count >= MAX_ATTEMPTS) {
            return Status.EXHAUSTED;
        }
        return Status.WRONG;
    }

    /** 저장된 실패 횟수. 없거나 숫자가 아니면 0. */
    private long attemptsUsed(Flow flow, String email) {
        String raw = redis.opsForValue().get(attemptsKey(flow, email));
        if (raw == null || raw.isBlank()) {
            return 0;
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    private static String codeHash(String email, String code) {
        String address = email == null ? "" : email;
        String submitted = code == null ? "" : code;
        return RefreshTokenDAO.hash(address + ":" + submitted);
    }

    private static String emailHash(String email) {
        return RefreshTokenDAO.hash(email == null ? "" : email);
    }

    private static String codeKey(Flow flow, String email) {
        return flow.prefix + emailHash(email);
    }

    private static String attemptsKey(Flow flow, String email) {
        return flow.prefix + "attempts:" + emailHash(email);
    }

    private static String cooldownKey(Flow flow, String email) {
        return flow.prefix + "cooldown:" + emailHash(email);
    }
}
