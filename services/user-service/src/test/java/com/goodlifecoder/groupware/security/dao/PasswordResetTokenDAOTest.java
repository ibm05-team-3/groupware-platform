package com.goodlifecoder.groupware.security.dao;

import com.goodlifecoder.groupware.common.config.MailProperties;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PasswordResetTokenDAOTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");

    @Test
    void issueStoresTheHashAndNotTheRawToken() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        when(values.get("auth:password-reset:user:" + USER_ID)).thenReturn(null);
        PasswordResetTokenDAO dao = dao(redis);

        String raw = dao.issue(USER_ID);

        String hash = RefreshTokenDAO.hash(raw);
        verify(values).set(eq("auth:password-reset:" + hash), eq(USER_ID.toString()), eq(Duration.ofMinutes(30)));
        verify(values).set(eq("auth:password-reset:user:" + USER_ID), eq(hash), eq(Duration.ofMinutes(30)));
        assertThat(raw).doesNotContain(hash);
    }

    @Test
    void consumeReadsTheHashOnce() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        when(values.getAndDelete(any())).thenReturn(USER_ID.toString());
        when(values.get(any())).thenReturn("stored-hash");
        PasswordResetTokenDAO dao = dao(redis);

        Optional<UUID> userId = dao.consume("raw-token");

        assertThat(userId).contains(USER_ID);
        verify(values).getAndDelete("auth:password-reset:" + RefreshTokenDAO.hash("raw-token"));
    }

    private static PasswordResetTokenDAO dao(StringRedisTemplate redis) {
        MailProperties mailProperties = new MailProperties(
                true, "roomlink@gmail.com", "Groupware", "http://localhost:5173", Duration.ofMinutes(30));
        return new PasswordResetTokenDAO(redis, mailProperties);
    }
}
