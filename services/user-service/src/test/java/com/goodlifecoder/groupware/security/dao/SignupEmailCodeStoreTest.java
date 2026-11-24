package com.goodlifecoder.groupware.security.dao;

import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Flow;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Status;
import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SignupEmailCodeStoreTest {

    private static final String EMAIL = "person@gmail.com";

    private StringRedisTemplate redis;
    private ValueOperations<String, String> values;
    private SignupEmailCodeStore store;

    @BeforeEach
    void setUp() {
        redis = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> operations = mock(ValueOperations.class);
        values = operations;
        when(redis.opsForValue()).thenReturn(values);
        store = new SignupEmailCodeStore(redis);
    }

    @Test
    void issueStoresAHashOfA32ByteTokenForTenMinutes() {
        String code = store.issue(Flow.SIGNUP, EMAIL);

        assertThat(Base64.getUrlDecoder().decode(code)).hasSize(32);
        verify(values).set(
                eq(codeKey(Flow.SIGNUP)),
                eq(RefreshTokenDAO.hash(EMAIL + ":" + code)),
                eq(Duration.ofMinutes(10)));
        verify(redis).delete(attemptsKey(Flow.SIGNUP));
        assertThat(RefreshTokenDAO.hash(EMAIL + ":" + code)).doesNotContain(EMAIL);
    }

    @Test
    void rootCodeUsesASeparateKey() {
        String code = store.issue(Flow.ROOT, EMAIL);

        verify(values).set(
                eq(codeKey(Flow.ROOT)),
                eq(RefreshTokenDAO.hash(EMAIL + ":" + code)),
                eq(Duration.ofMinutes(10)));
    }

    @Test
    void matchingCodeIsConsumed() {
        String stored = RefreshTokenDAO.hash(EMAIL + ":042317");
        when(values.get(codeKey(Flow.SIGNUP))).thenReturn(stored);

        assertThat(store.check(Flow.SIGNUP, EMAIL, "042317")).isEqualTo(Status.MATCH);

        verify(redis).delete(codeKey(Flow.SIGNUP));
        verify(redis).delete(attemptsKey(Flow.SIGNUP));
        verify(values, never()).increment(any());
    }

    @Test
    void wrongAndExpiredCodesCountAsFailures() {
        when(values.get(codeKey(Flow.SIGNUP))).thenReturn(null);
        when(values.increment(attemptsKey(Flow.SIGNUP))).thenReturn(1L);

        assertThat(store.check(Flow.SIGNUP, EMAIL, "000000")).isEqualTo(Status.WRONG);

        verify(redis).expire(attemptsKey(Flow.SIGNUP), Duration.ofMinutes(10));
        verify(redis, never()).delete(codeKey(Flow.SIGNUP));
    }

    @Test
    void fifthFailureKeepsTheCode() {
        when(values.get(codeKey(Flow.SIGNUP))).thenReturn(RefreshTokenDAO.hash(EMAIL + ":042317"));
        when(values.increment(attemptsKey(Flow.SIGNUP))).thenReturn(5L);

        assertThat(store.check(Flow.SIGNUP, EMAIL, "000000")).isEqualTo(Status.EXHAUSTED);

        verify(redis, never()).delete(codeKey(Flow.SIGNUP));
    }

    @Test
    void attemptsPastFiveStopWithoutAnotherFailure() {
        when(values.get(attemptsKey(Flow.SIGNUP))).thenReturn("5");

        assertThat(store.check(Flow.SIGNUP, EMAIL, "042317")).isEqualTo(Status.EXHAUSTED);

        verify(values, never()).increment(any());
        verify(values, never()).get(codeKey(Flow.SIGNUP));
        verify(redis, never()).delete(anyString());
    }

    @Test
    void rememberSendStartsASixtySecondCooldown() {
        store.rememberSend(Flow.SIGNUP, EMAIL);

        verify(values).set(cooldownKey(Flow.SIGNUP), "1", Duration.ofSeconds(60));
    }

    private static String codeKey(Flow flow) {
        String prefix = flow == Flow.SIGNUP ? "auth:signup-code:" : "auth:root-signup-code:";
        return prefix + RefreshTokenDAO.hash(EMAIL);
    }

    private static String attemptsKey(Flow flow) {
        String prefix = flow == Flow.SIGNUP ? "auth:signup-code:" : "auth:root-signup-code:";
        return prefix + "attempts:" + RefreshTokenDAO.hash(EMAIL);
    }

    private static String cooldownKey(Flow flow) {
        String prefix = flow == Flow.SIGNUP ? "auth:signup-code:" : "auth:root-signup-code:";
        return prefix + "cooldown:" + RefreshTokenDAO.hash(EMAIL);
    }
}
