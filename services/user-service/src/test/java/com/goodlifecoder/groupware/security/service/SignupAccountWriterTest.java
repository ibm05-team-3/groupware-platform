package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.service.SignupService.EmailAlreadyUsedException;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SignupAccountWriterTest {

    private final UserRepository users = mock(UserRepository.class);
    private final UnverifiedUserDeleter deleter = mock(UnverifiedUserDeleter.class);
    private final ConfirmedAccountWriter confirmed = mock(ConfirmedAccountWriter.class);
    private final SignupAccountWriter writer = new SignupAccountWriter(users, deleter, confirmed);

    @Test
    void createsWhenTheEmailIsFree() {
        when(users.findByEmail("person@gmail.com")).thenReturn(Optional.empty());

        writer.create("person@gmail.com", "{noop}secret");

        verify(confirmed).insert("person@gmail.com", "{noop}secret");
        verify(deleter, never()).deleteIfUnverified(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void replacesAnUnverifiedRow() {
        when(users.findByEmail("person@gmail.com")).thenReturn(Optional.of(account(false)));

        writer.create("person@gmail.com", "{noop}secret");

        verify(deleter).deleteIfUnverified(7L);
        verify(confirmed).insert("person@gmail.com", "{noop}secret");
    }

    @Test
    void rejectsAnActiveAccount() {
        when(users.findByEmail("person@gmail.com")).thenReturn(Optional.of(account(true)));

        assertThatThrownBy(() -> writer.create("person@gmail.com", "{noop}secret"))
                .isInstanceOf(EmailAlreadyUsedException.class);
        verify(confirmed, never()).insert(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    private static UserEntity account(boolean enabled) {
        return UserEntity.builder()
                .id(7L)
                .enabled(enabled)
                .email("person@gmail.com")
                .password("{noop}old")
                .build();
    }
}
