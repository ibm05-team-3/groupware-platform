package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupTokenException;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UnverifiedSignupCleanupTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-10T18:00:00Z"), ZoneId.of("Asia/Seoul"));

    private final UserRepository users = mock(UserRepository.class);
    private final UnverifiedUserDeleter deleter = mock(UnverifiedUserDeleter.class);
    private final UnverifiedSignupCleanup cleanup = new UnverifiedSignupCleanup(users, deleter, CLOCK);

    @Test
    void remainingIsEmptyAtSevenDays() {
        UserEntity user = user(seoul(2026, 11, 4));

        assertThat(cleanup.remaining(user)).isEmpty();
    }

    @Test
    void remainingKeepsTheRestOfTheSevenDays() {
        UserEntity user = user(seoul(2026, 11, 5));

        assertThat(cleanup.remaining(user)).contains(java.time.Duration.ofDays(1));
    }

    @Test
    void purgeDeletesOnlyTheReturnedRows() {
        when(users.findUnverifiedCreatedBefore(OffsetDateTime.now(CLOCK).minus(java.time.Duration.ofDays(7))))
                .thenReturn(List.of(account(4L), account(9L)));

        assertThat(cleanup.purgeExpired()).isEqualTo(2);
        verify(deleter).deleteIfUnverified(4L);
        verify(deleter).deleteIfUnverified(9L);
    }

    @Test
    void confirmLegacyActivatesAFreshAccount() {
        UserEntity user = user(seoul(2026, 11, 10));
        user.changePassword("{noop}old");
        trySetEmail(user, "person@gmail.com");
        when(users.findById(7L)).thenReturn(Optional.of(user));

        cleanup.confirmLegacy(7L);

        assertThat(user.isEnabled()).isTrue();
        verify(users).save(user);
        verify(deleter, never()).deleteIfUnverified(7L);
    }

    @Test
    void confirmLegacyDeletesAnExpiredAccount() {
        UserEntity user = user(null);
        when(users.findById(7L)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> cleanup.confirmLegacy(7L)).isInstanceOf(InvalidSignupTokenException.class);
        verify(deleter).deleteIfUnverified(7L);
        verify(users, never()).save(user);
    }

    private static OffsetDateTime seoul(int year, int month, int day) {
        return OffsetDateTime.of(year, month, day, 3, 0, 0, 0, ZoneOffset.ofHours(9));
    }

    private static UserEntity user(OffsetDateTime createdAt) {
        UserEntity user = UserEntity.builder().id(7L).enabled(false).build();
        ReflectionTestUtils.setField(user, "createdAt", createdAt);
        return user;
    }

    private static UserEntity account(long userId) {
        return UserEntity.builder()
                .id(userId)
                .enabled(false)
                .email("person@gmail.com")
                .password("{noop}old")
                .build();
    }

    private static void trySetEmail(UserEntity user, String email) {
        ReflectionTestUtils.setField(user, "email", email);
    }
}
