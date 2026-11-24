package com.goodlifecoder.groupware.user.service;

import com.goodlifecoder.groupware.security.service.AuthService;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AccountWithdrawalServiceTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");

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
                .id(USER_ID)
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
        verify(socialAccountRepository).deleteByUserId(USER_ID);
        verify(authService).revokeUser(USER_ID.toString(), "current-session");
    }
}
