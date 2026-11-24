package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.service.SignupService.EmailAlreadyUsedException;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ConfirmedAccountWriterTest {

    private final UserRepository users = mock(UserRepository.class);
    private final ConfirmedAccountWriter writer = new ConfirmedAccountWriter(users);

    @Test
    void insertsAnEnabledAccountWithTheGivenPasswordHash() {
        when(users.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        writer.insert("person@gmail.com", "{noop}secret");

        verify(users).saveAndFlush(org.mockito.ArgumentMatchers.argThat(user ->
                user.isEnabled()
                        && "person@gmail.com".equals(user.getEmail())
                        && "{noop}secret".equals(user.getPassword())));
    }

    @Test
    void duplicateInsertIsRejected() {
        when(users.saveAndFlush(any(UserEntity.class)))
                .thenThrow(new DataIntegrityViolationException("duplicate"));

        assertThatThrownBy(() -> writer.insert("person@gmail.com", "{noop}secret"))
                .isInstanceOf(EmailAlreadyUsedException.class);
    }
}
