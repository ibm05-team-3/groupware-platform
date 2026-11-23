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
import java.util.UUID;
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
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");
    private static final UUID FOUR = UUID.fromString("00000000-0000-0000-0000-000000000004");
    private static final UUID NINE = UUID.fromString("00000000-0000-0000-0000-000000000009");

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
                .thenReturn(List.of(account(FOUR), account(NINE)));

        assertThat(cleanup.purgeExpired()).isEqualTo(2);
        verify(deleter).deleteIfUnverified(FOUR);
        verify(deleter).deleteIfUnverified(NINE);
    }

    @Test
    void confirmLegacyActivatesAFreshAccount() {
        UserEntity user = user(seoul(2026, 11, 10));
        user.changePassword("{noop}old");
        trySetEmail(user, "person@gmail.com");
        when(users.findById(USER_ID)).thenReturn(Optional.of(user));

        cleanup.confirmLegacy(USER_ID);

        assertThat(user.isEnabled()).isTrue();
        verify(users).save(user);
        verify(deleter, never()).deleteIfUnverified(USER_ID);
    }

    @Test
    void confirmLegacyDeletesAnExpiredAccount() {
        UserEntity user = user(null);
        when(users.findById(USER_ID)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> cleanup.confirmLegacy(USER_ID)).isInstanceOf(InvalidSignupTokenException.class);
        verify(deleter).deleteIfUnverified(USER_ID);
        verify(users, never()).save(user);
    }

    private static OffsetDateTime seoul(int year, int month, int day) {
        return OffsetDateTime.of(year, month, day, 3, 0, 0, 0, ZoneOffset.ofHours(9));
    }

    private static UserEntity user(OffsetDateTime createdAt) {
        UserEntity user = UserEntity.builder().id(USER_ID).enabled(false).build();
        ReflectionTestUtils.setField(user, "createdAt", createdAt);
        return user;
    }

    private static UserEntity account(UUID userId) {
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
