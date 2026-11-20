package com.goodlifecoder.groupware.user.service;

import com.goodlifecoder.groupware.security.service.AuthService;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AccountWithdrawalServiceTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final SocialAccountRepository socialAccountRepository = mock(SocialAccountRepository.class);
    private final AuthService authService = mock(AuthService.class);
    private final AccountWithdrawalService service = new AccountWithdrawalService(
            userRepository,
            socialAccountRepository,
            authService
    );

    @Test
    void withdrawClearsLoginColumnsAndRevokesSessions() {
        UserEntity user = UserEntity.builder()
                .id(7L)
                .nickname("민수")
                .email("person@gmail.com")
                .password("{noop}secret")
                .enabled(true)
                .build();

        service.withdraw(user, "current-session");

        assertThat(user.isEnabled()).isFalse();
        assertThat(user.getNickname()).isNull();
        assertThat(user.getEmail()).isNull();
        assertThat(user.getPassword()).isNull();
        verify(userRepository).saveAndFlush(user);
        verify(socialAccountRepository).deleteByUserId(7L);
        verify(authService).revokeUser("7", "current-session");
    }
}
