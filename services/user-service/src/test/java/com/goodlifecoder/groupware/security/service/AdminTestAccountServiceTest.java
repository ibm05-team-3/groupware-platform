package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.dao.PendingSignupStore;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Flow;
import com.goodlifecoder.groupware.security.service.SignupService.EmailAlreadyUsedException;
import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupException;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AdminTestAccountServiceTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");

    private final UserRepository users = mock(UserRepository.class);
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private final PendingSignupStore pending = mock(PendingSignupStore.class);
    private final SignupEmailCodeStore codes = mock(SignupEmailCodeStore.class);
    private final UnverifiedSignupCleanup cleanup = mock(UnverifiedSignupCleanup.class);
    private final ConfirmedAccountWriter writer = mock(ConfirmedAccountWriter.class);
    private final AdminTestAccountService service =
            new AdminTestAccountService(users, encoder, pending, codes, cleanup, writer);

    @Test
    void createsAnActiveAccountWithoutMail() {
        when(users.findByEmail("person@test.com")).thenReturn(Optional.empty());
        when(encoder.encode("secret")).thenReturn("{noop}secret");

        service.create("  Person@Test.com ", "secret");

        verify(pending).delete("person@test.com");
        verify(codes).revoke(Flow.SIGNUP, "person@test.com");
        verify(writer).insert("person@test.com", "{noop}secret");
        verify(cleanup, never()).deleteUnverified(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void duplicateEmailIsRejected() {
        when(users.findByEmail("person@test.com")).thenReturn(Optional.of(account(true)));

        assertThatThrownBy(() -> service.create("person@test.com", "secret"))
                .isInstanceOf(EmailAlreadyUsedException.class);
        verify(writer, never()).insert(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void unverifiedEmailIsReplaced() {
        when(users.findByEmail("person@test.com")).thenReturn(Optional.of(account(false)));
        when(encoder.encode("secret")).thenReturn("{noop}secret");

        service.create("person@test.com", "secret");

        verify(cleanup).deleteUnverified(USER_ID);
        verify(writer).insert("person@test.com", "{noop}secret");
    }

    @Test
    void blankPasswordIsRejected() {
        assertThatThrownBy(() -> service.create("person@test.com", " "))
                .isInstanceOf(InvalidSignupException.class);
        verifyNoInteractions(users, pending, codes, cleanup, writer);
    }

    private static UserEntity account(boolean enabled) {
        return UserEntity.builder()
                .id(USER_ID)
                .enabled(enabled)
                .email("person@test.com")
                .password("{noop}old")
                .build();
    }
}
