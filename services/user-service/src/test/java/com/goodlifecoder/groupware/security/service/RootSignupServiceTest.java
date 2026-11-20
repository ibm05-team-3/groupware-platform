package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.common.config.MailProperties;
import com.goodlifecoder.groupware.security.dao.RootSignupStore;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Flow;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Status;
import com.goodlifecoder.groupware.security.mail.SignupVerificationMailSender;
import com.goodlifecoder.groupware.security.service.SignupService.EmailAlreadyUsedException;
import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupException;
import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupTokenException;
import com.goodlifecoder.groupware.user.entity.SocialProviderType;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RootSignupServiceTest {

    private static final String EMAIL = "root@acme.com";

    private final UserRepository users = mock(UserRepository.class);
    private final SocialAccountRepository social = mock(SocialAccountRepository.class);
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private final SignupVerificationMailSender mail = mock(SignupVerificationMailSender.class);
    private final SignupMailRateLimiter limiter = mock(SignupMailRateLimiter.class);
    private final SignupEmailCodeStore codes = mock(SignupEmailCodeStore.class);
    private final RootSignupStore store = mock(RootSignupStore.class);
    private final MailProperties mailProperties = new MailProperties(true, "from@acme.com", "Acme", "http://localhost:5173", Duration.ofMinutes(30));
    private final RootSignupService service = new RootSignupService(
            users, social, encoder, mailProperties, mail, limiter, codes, store);

    @BeforeEach
    void defaults() {
        when(limiter.allow(any(), any())).thenReturn(true);
        when(users.findByEmail(any())).thenReturn(Optional.empty());
        when(store.remaining(any())).thenReturn(Optional.empty());
        when(store.findPending(any())).thenReturn(Optional.empty());
        when(codes.issue(eq(Flow.ROOT), any())).thenReturn("raw-token");
        when(encoder.encode("secret")).thenReturn("{noop}secret");
    }

    @Test
    void requestStoresTheEmailAndSendsACode() {
        service.request(" Root@Acme.com ", "203.0.113.5");

        verify(store).savePending(EMAIL, com.goodlifecoder.groupware.security.dao.PendingSignupStore.RETENTION);
        verify(mail).send(EMAIL, "raw-token");
        verify(codes).rememberSend(Flow.ROOT, EMAIL);
        verify(users, never()).save(any());
    }

    @Test
    void confirmIssuesAShortTokenWithoutCreatingAUser() {
        when(codes.check(Flow.ROOT, EMAIL, "raw-token")).thenReturn(Status.MATCH);
        when(store.findPending(EMAIL)).thenReturn(Optional.of(EMAIL));
        when(store.issueVerified(EMAIL)).thenReturn("signup-token");

        assertThat(service.confirmEmail(" Root@Acme.com ", "raw-token")).isEqualTo("signup-token");

        verify(store).deletePending(EMAIL);
        verify(users, never()).save(any());
    }

    @Test
    void confirmRejectsAWrongCode() {
        when(codes.check(Flow.ROOT, EMAIL, "000000")).thenReturn(Status.WRONG);

        assertThatThrownBy(() -> service.confirmEmail(EMAIL, "000000")).isInstanceOf(InvalidSignupTokenException.class);
        verify(store, never()).issueVerified(any());
    }

    @Test
    void passwordCreatesAnEnabledUser() {
        when(store.findVerified("signup-token")).thenReturn(Optional.of(EMAIL));
        when(users.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        service.completeWithPassword("signup-token", "secret");

        verify(users).saveAndFlush(org.mockito.ArgumentMatchers.argThat(user ->
                EMAIL.equals(user.getEmail())
                        && "{noop}secret".equals(user.getPassword())
                        && user.isEnabled()));
        verify(store).deleteVerified("signup-token");
    }

    @Test
    void socialRejectsADifferentEmail() {
        when(store.findVerified("signup-token")).thenReturn(Optional.of(EMAIL));

        assertThatThrownBy(() -> service.completeWithSocial(
                "signup-token",
                "other@gmail.com",
                "루트",
                "GOOGLE_sub",
                SocialProviderType.GOOGLE,
                "sub"))
                .isInstanceOf(InvalidSignupException.class);

        verify(users, never()).save(any());
        verify(store, never()).deleteVerified("signup-token");
    }

    @Test
    void socialCreatesAUserWhenTheEmailMatches() {
        when(store.findVerified("signup-token")).thenReturn(Optional.of(EMAIL));
        when(social.findById("GOOGLE_sub")).thenReturn(Optional.empty());
        when(users.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        UserEntity user = service.completeWithSocial(
                "signup-token", "Root@Acme.com", "루트", "GOOGLE_sub", SocialProviderType.GOOGLE, "sub");

        assertThat(user.getEmail()).isEqualTo(EMAIL);
        assertThat(user.getPassword()).isNull();
        verify(social).save(any());
        verify(store).deleteVerified("signup-token");
    }

    @Test
    void requestRejectsAnEmailThatAlreadyHasAUser() {
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(UserEntity.builder().id(1L).email(EMAIL).build()));

        assertThatThrownBy(() -> service.request(EMAIL, "203.0.113.5")).isInstanceOf(EmailAlreadyUsedException.class);
        verify(mail, never()).send(any(), any());
    }
}
