package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Flow;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UnverifiedUserDeleterTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");

    private final SocialAccountRepository social = mock(SocialAccountRepository.class);
    private final UserRepository users = mock(UserRepository.class);
    private final SignupEmailCodeStore codes = mock(SignupEmailCodeStore.class);
    private final UnverifiedUserDeleter deleter = new UnverifiedUserDeleter(social, users, codes);

    @Test
    void deletesADisabledEmailAccount() {
        UserEntity user = UserEntity.builder()
                .id(USER_ID)
                .enabled(false)
                .email("person@gmail.com")
                .password("{noop}old")
                .build();
        when(users.findById(USER_ID)).thenReturn(Optional.of(user));

        deleter.deleteIfUnverified(USER_ID);

        verify(social).deleteByUserId(USER_ID);
        verify(users).delete(user);
        verify(codes).revoke(Flow.SIGNUP, "person@gmail.com");
    }

    @Test
    void leavesAnEnabledAccount() {
        UserEntity user = UserEntity.builder()
                .id(USER_ID)
                .enabled(true)
                .email("person@gmail.com")
                .password("{noop}old")
                .build();
        when(users.findById(USER_ID)).thenReturn(Optional.of(user));

        deleter.deleteIfUnverified(USER_ID);

        verify(users, never()).delete(user);
        verify(codes, never()).revoke(any(), any());
    }
}
