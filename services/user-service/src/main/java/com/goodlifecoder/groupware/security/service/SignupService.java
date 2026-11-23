package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.common.config.MailProperties;
import com.goodlifecoder.groupware.security.dao.PendingSignupStore;
import com.goodlifecoder.groupware.security.dao.PendingSignupStore.PendingSignup;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Flow;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Status;
import com.goodlifecoder.groupware.security.mail.SignupVerificationMailSender;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import org.springframework.security.crypto.password.PasswordEncoder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * 메일이 꺼져 있으면 가입을 받지 않는다.
 * 메일이 켜져 있으면 확인 전까지 회원을 만들지 않는다. 대기 정보는 7일 뒤에 사라지고 그 이메일은 다시 쓸 수 있다.
 * 확인 토큰은 10분이다. 5번 틀리면 다시 보낼 때까지 확인을 거절한다. 재발송은 60초에 한 번이다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SignupService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final MailProperties mailProperties;
    private final SignupEmailCodeStore signupEmailCodeStore;
    private final SignupVerificationMailSender signupVerificationMailSender;
    private final PendingSignupStore pendingSignups;
    private final SignupMailRateLimiter signupMailRateLimiter;
    private final UnverifiedSignupCleanup unverifiedSignupCleanup;
    private final SignupAccountWriter signupAccountWriter;

    /** 이메일을 소문자로 맞춘다. null 은 빈 문자열이다. */
    public static String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    /** 가입을 접수하고 확인 메일을 보낸다. 활성 계정이 있으면 EmailAlreadyUsedException. */
    public void signup(String email, String password, String clientIp) {
        String normalized = normalizeEmail(email);
        if (!isEmail(normalized) || password == null || password.isBlank()) {
            throw new InvalidSignupException();
        }
        if (!mailProperties.enabled()) {
            throw new MailDisabledException();
        }
        ensureSendable(normalized);
        if (!signupMailRateLimiter.allow(normalized, clientIp)) {
            throw new TooManyRequestsException();
        }

        Optional<UserEntity> existing = userRepository.findByEmail(normalized);
        if (existing.isPresent() && existing.get().isEnabled()) {
            pendingSignups.delete(normalized);
            signupEmailCodeStore.revoke(Flow.SIGNUP, normalized);
            throw new EmailAlreadyUsedException();
        }

        Optional<Duration> pendingTtl = pendingSignups.remaining(normalized);
        Optional<Duration> legacyTtl = existing
                .map(unverifiedSignupCleanup::remaining)
                .orElse(Optional.empty());
        boolean replace = pendingTtl.isPresent() || legacyTtl.isPresent();
        Duration ttl = retention(pendingTtl, legacyTtl);
        if (existing.isPresent()) {
            unverifiedSignupCleanup.deleteUnverified(existing.get().getId());
        }
        pendingSignups.save(normalized, passwordEncoder.encode(password), ttl);
        send(normalized, replace);
    }

    /**
     * 기다리는 가입이 있으면 확인 메일을 다시 보낸다.
     * 없거나 이미 활성 회원이면 메일을 보내지 않고 그대로 끝낸다.
     */
    public void resend(String email, String clientIp) {
        String normalized = normalizeEmail(email);
        if (!isEmail(normalized)) {
            throw new InvalidSignupException();
        }
        if (!mailProperties.enabled()) {
            throw new MailDisabledException();
        }
        ensureSendable(normalized);
        if (!signupMailRateLimiter.allow(normalized, clientIp)) {
            throw new TooManyRequestsException();
        }
        if (pendingSignups.find(normalized).isEmpty()) {
            migrateLegacy(normalized);
        }
        if (pendingSignups.find(normalized).isEmpty()) {
            return;
        }
        send(normalized, true);
    }

    /** 토큰이 맞으면 활성 회원을 만든다. 틀리거나 대기가 없거나 이메일이 겹치면 InvalidSignupTokenException. 5회를 넘기면 TooManyAttemptsException. */
    public void confirmEmail(String email, String code) {
        String normalized = normalizeEmail(email);
        String submitted = code == null ? "" : code.trim();
        Status status = signupEmailCodeStore.check(Flow.SIGNUP, normalized, submitted);
        if (status == Status.EXHAUSTED) {
            throw new TooManyAttemptsException();
        }
        if (status != Status.MATCH) {
            throw new InvalidSignupTokenException();
        }
        Optional<PendingSignup> pending = pendingSignups.find(normalized);
        if (pending.isEmpty()) {
            throw new InvalidSignupTokenException();
        }
        try {
            signupAccountWriter.create(pending.get().email(), pending.get().passwordHash());
        } catch (EmailAlreadyUsedException ex) {
            pendingSignups.delete(pending.get().email());
            throw new InvalidSignupTokenException();
        }
        pendingSignups.delete(pending.get().email());
    }

    /** 60초 재발송 간격은 메일 횟수 한도보다 먼저 본다. */
    private void ensureSendable(String email) {
        if (signupEmailCodeStore.coolingDown(Flow.SIGNUP, email)) {
            throw new TooManyRequestsException();
        }
    }

    /** 비활성 행이 7일 안이면 Redis 대기로 옮기고 행은 지운다. 활성이거나 기한이 지났으면 그대로 둔다. */
    private void migrateLegacy(String email) {
        Optional<UserEntity> existing = userRepository.findByEmail(email);
        if (existing.isEmpty() || existing.get().isEnabled()) {
            return;
        }
        UserEntity user = existing.get();
        Optional<Duration> remaining = unverifiedSignupCleanup.remaining(user);
        if (remaining.isEmpty()) {
            return;
        }
        pendingSignups.save(email, user.getPassword(), remaining.get());
        unverifiedSignupCleanup.deleteUnverified(user.getId());
    }

    /** 확인 코드를 보낸다. 첫 발송이 실패하면 대기 가입을 지우고, 다시 보내기 실패면 대기 가입은 남긴다. 성공한 뒤에만 60초를 센다. */
    private void send(String email, boolean keepPendingOnFailure) {
        String code = signupEmailCodeStore.issue(Flow.SIGNUP, email);
        try {
            signupVerificationMailSender.send(email, code);
        } catch (RuntimeException ex) {
            signupEmailCodeStore.revoke(Flow.SIGNUP, email);
            if (!keepPendingOnFailure) {
                pendingSignups.delete(email);
            }
            log.warn("회원가입 확인 메일 발송 실패. to={}", email);
            throw new MailSendException();
        }
        signupEmailCodeStore.rememberSend(Flow.SIGNUP, email);
    }

    /** 대기와 예전 행의 남은 시간 중 짧은 쪽. 둘 다 없으면 7일. */
    private static Duration retention(Optional<Duration> pendingTtl, Optional<Duration> legacyTtl) {
        if (pendingTtl.isPresent() && legacyTtl.isPresent()) {
            return pendingTtl.get().compareTo(legacyTtl.get()) <= 0 ? pendingTtl.get() : legacyTtl.get();
        }
        if (pendingTtl.isPresent()) {
            return pendingTtl.get();
        }
        if (legacyTtl.isPresent()) {
            return legacyTtl.get();
        }
        return PendingSignupStore.RETENTION;
    }

    /** @ 와 도메인 점이 있는지만 본다. */
    private static boolean isEmail(String email) {
        int at = email.indexOf('@');
        return at > 0
                && email.indexOf('.', at + 1) > at + 1
                && !email.contains(" ")
                && !email.contains("\n")
                && !email.contains("\r");
    }

    /**
     * 이메일이나 비밀번호가 비어 있거나 이메일 형식이 아닐 때.
     *
     * @author 조휘재
     * 작성일: 2026-11-23
     */
    public static class InvalidSignupException extends RuntimeException {
    }

    /**
     * 같은 이메일 계정이 이미 있을 때.
     *
     * @author 조휘재
     * 작성일: 2026-11-23
     */
    public static class EmailAlreadyUsedException extends RuntimeException {
    }

    /**
     * 메일이 꺼져 있어 가입을 받지 않을 때.
     *
     * @author 조휘재
     * 작성일: 2026-11-23
     */
    public static class MailDisabledException extends RuntimeException {
    }

    /**
     * 확인 메일을 보내지 못했을 때.
     *
     * @author 조휘재
     * 작성일: 2026-11-23
     */
    public static class MailSendException extends RuntimeException {
    }

    /**
     * 확인 코드가 없거나 틀리거나 만료됐을 때. 그 이메일로 활성 회원이 이미 있으면 여기로 바꾼다.
     *
     * @author 조휘재
     * 작성일: 2026-11-23
     */
    public static class InvalidSignupTokenException extends RuntimeException {
    }

    /**
     * 확인 토큰을 5번 틀린 뒤. 토큰은 남아 있고, 다시 보내면 횟수가 되돌아간다.
     */
    public static class TooManyAttemptsException extends RuntimeException {
    }

    /**
     * 가입 확인 메일이 이메일 또는 IP 한도를 넘었을 때.
     *
     * @author 조휘재
     * 작성일: 2026-11-23
     */
    public static class TooManyRequestsException extends RuntimeException {
    }
}
