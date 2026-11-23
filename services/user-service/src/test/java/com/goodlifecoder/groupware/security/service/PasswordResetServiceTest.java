package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.common.config.MailProperties;
import com.goodlifecoder.groupware.security.dao.PasswordResetTokenDAO;
import com.goodlifecoder.groupware.security.mail.PasswordResetMailDispatcher;
import com.goodlifecoder.groupware.security.service.PasswordResetService.InvalidPasswordResetException;
import com.goodlifecoder.groupware.security.service.PasswordResetService.InvalidPasswordResetTokenException;
import com.goodlifecoder.groupware.security.service.PasswordResetService.MailDisabledException;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.RejectedExecutionException;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class PasswordResetServiceTest {

    private static final String IP = "203.0.113.5";
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");

    private final UserRepository users = mock(UserRepository.class);
    private final PasswordResetTokenDAO tokens = mock(PasswordResetTokenDAO.class);
    private final PasswordResetMailDispatcher mail = mock(PasswordResetMailDispatcher.class);
    private final PasswordResetRateLimiter limits = mock(PasswordResetRateLimiter.class);
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private final AuthService auth = mock(AuthService.class);

    @Test
    void mailDisabledDoesNotLookUpOrSend() {
        PasswordResetService service = service(false);

        assertThatThrownBy(() -> service.requestReset("resident-a@test.com", IP))
                .isInstanceOf(MailDisabledException.class);
        verifyNoInteractions(users, tokens, mail, limits);
    }

    @Test
    void mailEnabledSchedulesTheLinkAndDoesNotWaitForIt() {
        PasswordResetService service = service(true);
        when(limits.allow("resident-a@test.com", IP)).thenReturn(true);
        when(users.findByEmail("resident-a@test.com")).thenReturn(Optional.of(account()));
        when(tokens.issue(USER_ID)).thenReturn("raw-token");

        service.requestReset("  Resident-A@test.com ", IP);

        verify(mail).send(
                USER_ID,
                "resident-a@test.com",
                "http://localhost:5173/password-reset?token=raw-token");
    }

    @Test
    void unknownEmailDoesNotSend() {
        PasswordResetService service = service(true);
        when(limits.allow("missing@naver.com", IP)).thenReturn(true);
        when(users.findByEmail("missing@naver.com")).thenReturn(Optional.empty());

        service.requestReset("missing@naver.com", IP);

        verifyNoInteractions(tokens, mail);
    }

    @Test
    void overLimitMatchesAnUnknownEmail() {
        PasswordResetService service = service(true);
        when(limits.allow("resident-a@test.com", IP)).thenReturn(false);

        service.requestReset("resident-a@test.com", IP);

        verifyNoInteractions(users, tokens, mail);
    }

    @Test
    void scheduleFailureRevokesTheTokenAndDoesNotThrow() {
        PasswordResetService service = service(true);
        when(limits.allow("resident-a@test.com", IP)).thenReturn(true);
        when(users.findByEmail("resident-a@test.com")).thenReturn(Optional.of(account()));
        when(tokens.issue(USER_ID)).thenReturn("raw-token");
        doThrow(new RejectedExecutionException("full"))
                .when(mail)
                .send(USER_ID, "resident-a@test.com", "http://localhost:5173/password-reset?token=raw-token");

        service.requestReset("resident-a@test.com", IP);

        verify(tokens).revoke(USER_ID);
    }

    @Test
    void confirmReplacesPasswordAndRevokesSessions() {
        PasswordResetService service = service(true);
        UserEntity account = account();
        when(tokens.consume("raw-token")).thenReturn(Optional.of(USER_ID));
        when(users.findById(USER_ID)).thenReturn(Optional.of(account));
        when(encoder.encode("new-secret")).thenReturn("{noop}new-secret");

        service.confirm("raw-token", "new-secret");

        assertThat(account.getPassword()).isEqualTo("{noop}new-secret");
        verify(users).save(account);
        verify(auth).revokeUser(USER_ID.toString(), null);
    }

    @Test
    void confirmRejectsAUsedToken() {
        PasswordResetService service = service(true);
        when(tokens.consume("used")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.confirm("used", "new-secret"))
                .isInstanceOf(InvalidPasswordResetTokenException.class);
        verify(encoder, never()).encode(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void blankPasswordIsRejected() {
        PasswordResetService service = service(true);

        assertThatThrownBy(() -> service.confirm("raw-token", " "))
                .isInstanceOf(InvalidPasswordResetException.class);
        verifyNoInteractions(tokens, users, encoder, auth);
    }

    private PasswordResetService service(boolean enabled) {
        MailProperties mailProperties = new MailProperties(
                enabled, "roomlink@gmail.com", "Roomlink", "http://localhost:5173", Duration.ofMinutes(30));
        return new PasswordResetService(mailProperties, users, tokens, mail, limits, encoder, auth);
    }

    private static UserEntity account() {
        return UserEntity.builder()
                .id(USER_ID)
                .email("resident-a@test.com")
                .password("{noop}old")
                .build();
    }
}
