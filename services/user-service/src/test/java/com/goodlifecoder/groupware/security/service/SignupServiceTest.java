package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.common.config.MailProperties;
import com.goodlifecoder.groupware.security.dao.PendingSignupStore;
import com.goodlifecoder.groupware.security.dao.PendingSignupStore.PendingSignup;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Flow;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Status;
import com.goodlifecoder.groupware.security.mail.SignupVerificationMailSender;
import com.goodlifecoder.groupware.security.service.SignupService.EmailAlreadyUsedException;
import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupException;
import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupTokenException;
import com.goodlifecoder.groupware.security.service.SignupService.MailDisabledException;
import com.goodlifecoder.groupware.security.service.SignupService.MailSendException;
import com.goodlifecoder.groupware.security.service.SignupService.TooManyAttemptsException;
import com.goodlifecoder.groupware.security.service.SignupService.TooManyRequestsException;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class SignupServiceTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");
    private static final String EMAIL = "person@gmail.com";
    private static final String IP = "203.0.113.5";

    private final UserRepository users = mock(UserRepository.class);
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private final SignupEmailCodeStore codes = mock(SignupEmailCodeStore.class);
    private final SignupVerificationMailSender mail = mock(SignupVerificationMailSender.class);
    private final PendingSignupStore pending = mock(PendingSignupStore.class);
    private final SignupMailRateLimiter limiter = mock(SignupMailRateLimiter.class);
    private final UnverifiedSignupCleanup cleanup = mock(UnverifiedSignupCleanup.class);
    private final SignupAccountWriter writer = mock(SignupAccountWriter.class);

    @BeforeEach
    void defaults() {
        when(limiter.allow(any(), any())).thenReturn(true);
        when(users.findByEmail(any())).thenReturn(Optional.empty());
        when(pending.remaining(any())).thenReturn(Optional.empty());
        when(pending.find(any())).thenReturn(Optional.empty());
        when(codes.issue(eq(Flow.SIGNUP), any())).thenReturn("raw-token");
    }

    @Test
    void mailDisabledRejectsBeforeLookup() {
        SignupService service = service(false);

        assertThatThrownBy(() -> service.signup(EMAIL, "secret", IP)).isInstanceOf(MailDisabledException.class);
        verifyNoInteractions(users, encoder, codes, mail, pending, limiter, cleanup, writer);
    }

    @Test
    void signupKeepsTheAddressPendingUntilConfirmation() {
        SignupService service = service(true);
        when(encoder.encode("secret")).thenReturn("{noop}secret");

        service.signup("  Person@Gmail.com ", "secret", IP);

        verify(pending).save(EMAIL, "{noop}secret", PendingSignupStore.RETENTION);
        verify(mail).send(EMAIL, "raw-token");
        verify(codes).rememberSend(Flow.SIGNUP, EMAIL);
        verifyNoInteractions(writer);
        verify(cleanup, never()).deleteUnverified(any());
    }

    @Test
    void mailSendFailureDropsANewPendingSignup() {
        SignupService service = service(true);
        when(encoder.encode("secret")).thenReturn("{noop}secret");
        doThrow(new IllegalStateException("smtp")).when(mail).send(EMAIL, "raw-token");

        assertThatThrownBy(() -> service.signup(EMAIL, "secret", IP)).isInstanceOf(MailSendException.class);
        verify(codes).revoke(Flow.SIGNUP, EMAIL);
        verify(codes, never()).rememberSend(any(), any());
        verify(pending).delete(EMAIL);
        verifyNoInteractions(writer);
    }

    @Test
    void signupAgainKeepsTheOriginalWindow() {
        SignupService service = service(true);
        when(pending.remaining(EMAIL)).thenReturn(Optional.of(Duration.ofDays(2)));
        when(encoder.encode("secret")).thenReturn("{noop}secret");

        service.signup(EMAIL, "secret", IP);

        verify(pending).save(EMAIL, "{noop}secret", Duration.ofDays(2));
        verify(pending, never()).delete(any());
        verify(mail).send(EMAIL, "raw-token");
    }

    @Test
    void activeEmailIsRejected() {
        SignupService service = service(true);
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(account(true)));

        assertThatThrownBy(() -> service.signup(EMAIL, "secret", IP)).isInstanceOf(EmailAlreadyUsedException.class);
        verify(pending).delete(EMAIL);
        verify(codes).revoke(Flow.SIGNUP, EMAIL);
        verifyNoInteractions(mail, writer);
    }

    @Test
    void expiredUnverifiedAccountIsDeletedAndStartedAgain() {
        SignupService service = service(true);
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(account(false)));
        when(cleanup.remaining(any())).thenReturn(Optional.empty());
        when(encoder.encode("secret")).thenReturn("{noop}secret");

        service.signup(EMAIL, "secret", IP);

        verify(cleanup).deleteUnverified(USER_ID);
        verify(pending).save(EMAIL, "{noop}secret", PendingSignupStore.RETENTION);
    }

    @Test
    void freshUnverifiedAccountKeepsTheRemainingTime() {
        SignupService service = service(true);
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(account(false)));
        when(cleanup.remaining(any())).thenReturn(Optional.of(Duration.ofDays(3)));
        when(encoder.encode("secret")).thenReturn("{noop}secret");

        service.signup(EMAIL, "secret", IP);

        verify(cleanup).deleteUnverified(USER_ID);
        verify(pending).save(EMAIL, "{noop}secret", Duration.ofDays(3));
        verify(mail).send(eq(EMAIL), any());
    }

    @Test
    void tooManyRequestsStopsBeforeLookup() {
        SignupService service = service(true);
        when(limiter.allow(EMAIL, IP)).thenReturn(false);

        assertThatThrownBy(() -> service.signup(EMAIL, "secret", IP)).isInstanceOf(TooManyRequestsException.class);
        verifyNoInteractions(users, mail, pending, writer);
    }

    @Test
    void blankPasswordIsRejected() {
        SignupService service = service(true);

        assertThatThrownBy(() -> service.signup(EMAIL, " ", IP)).isInstanceOf(InvalidSignupException.class);
        verifyNoInteractions(users, limiter, mail, pending);
    }

    @Test
    void resendSendsWhenASignupIsWaiting() {
        SignupService service = service(true);
        when(pending.find(EMAIL)).thenReturn(Optional.of(new PendingSignup(EMAIL, "{noop}secret")));

        service.resend(EMAIL, IP);

        verify(mail).send(EMAIL, "raw-token");
        verify(codes).rememberSend(Flow.SIGNUP, EMAIL);
        verify(users, never()).findByEmail(any());
    }

    @Test
    void resendWithoutAWaitingSignupDoesNotSend() {
        SignupService service = service(true);

        service.resend(EMAIL, IP);

        verifyNoInteractions(mail, writer);
    }

    @Test
    void resendMovesAFreshUnverifiedAccountOutOfTheMemberTable() {
        SignupService service = service(true);
        when(pending.find(EMAIL)).thenReturn(Optional.empty(), Optional.of(new PendingSignup(EMAIL, "{noop}old")));
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(account(false)));
        when(cleanup.remaining(any())).thenReturn(Optional.of(Duration.ofDays(3)));

        service.resend(EMAIL, IP);

        verify(pending).save(EMAIL, "{noop}old", Duration.ofDays(3));
        verify(cleanup).deleteUnverified(USER_ID);
        verify(mail).send(eq(EMAIL), any());
        verifyNoInteractions(encoder);
    }

    @Test
    void resendOverTheLimitDoesNotLookUp() {
        SignupService service = service(true);
        when(limiter.allow(EMAIL, IP)).thenReturn(false);

        assertThatThrownBy(() -> service.resend(EMAIL, IP)).isInstanceOf(TooManyRequestsException.class);
        verifyNoInteractions(users, pending, mail);
    }

    @Test
    void cooldownRejectsBeforeTheMailLimit() {
        SignupService service = service(true);
        when(codes.coolingDown(Flow.SIGNUP, EMAIL)).thenReturn(true);

        assertThatThrownBy(() -> service.signup(EMAIL, "secret", IP)).isInstanceOf(TooManyRequestsException.class);
        verify(limiter, never()).allow(any(), any());
        verify(codes, never()).issue(any(), any());
    }

    @Test
    void confirmCreatesAnActiveAccount() {
        SignupService service = service(true);
        when(codes.check(Flow.SIGNUP, EMAIL, "raw-token")).thenReturn(Status.MATCH);
        when(pending.find(EMAIL)).thenReturn(Optional.of(new PendingSignup(EMAIL, "{noop}secret")));

        service.confirmEmail(" Person@Gmail.com ", "raw-token");

        verify(writer).create(EMAIL, "{noop}secret");
        verify(pending).delete(EMAIL);
    }

    @Test
    void confirmRejectsAWrongCode() {
        SignupService service = service(true);
        when(codes.check(Flow.SIGNUP, EMAIL, "000000")).thenReturn(Status.WRONG);

        assertThatThrownBy(() -> service.confirmEmail(EMAIL, "000000")).isInstanceOf(InvalidSignupTokenException.class);
        verifyNoInteractions(writer);
    }

    @Test
    void confirmStopsAfterFiveFailures() {
        SignupService service = service(true);
        when(codes.check(Flow.SIGNUP, EMAIL, "000000")).thenReturn(Status.EXHAUSTED);

        assertThatThrownBy(() -> service.confirmEmail(EMAIL, "000000")).isInstanceOf(TooManyAttemptsException.class);
        verifyNoInteractions(writer, pending);
    }

    @Test
    void confirmDropsACodeWhosePendingSignupIsGone() {
        SignupService service = service(true);
        when(codes.check(Flow.SIGNUP, EMAIL, "raw-token")).thenReturn(Status.MATCH);
        when(pending.find(EMAIL)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.confirmEmail(EMAIL, "raw-token")).isInstanceOf(InvalidSignupTokenException.class);
        verifyNoInteractions(writer);
    }

    @Test
    void confirmOfATakenEmailInvalidatesThePendingSignup() {
        SignupService service = service(true);
        when(codes.check(Flow.SIGNUP, EMAIL, "raw-token")).thenReturn(Status.MATCH);
        when(pending.find(EMAIL)).thenReturn(Optional.of(new PendingSignup(EMAIL, "{noop}secret")));
        doThrow(new EmailAlreadyUsedException()).when(writer).create(EMAIL, "{noop}secret");

        assertThatThrownBy(() -> service.confirmEmail(EMAIL, "raw-token")).isInstanceOf(InvalidSignupTokenException.class);
        verify(pending).delete(EMAIL);
    }

    private SignupService service(boolean mailEnabled) {
        MailProperties properties = new MailProperties(
                mailEnabled, "roomlink@gmail.com", "Roomlink", "http://localhost:5173", Duration.ofMinutes(30));
        return new SignupService(
                users, encoder, properties, codes, mail, pending, limiter, cleanup, writer);
    }

    private static UserEntity account(boolean enabled) {
        return UserEntity.builder()
                .id(USER_ID)
                .enabled(enabled)
                .email(EMAIL)
                .password("{noop}old")
                .build();
    }
}
