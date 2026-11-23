package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.common.config.MailProperties;
import com.goodlifecoder.groupware.security.dao.PendingSignupStore;
import com.goodlifecoder.groupware.security.dao.RootSignupStore;
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
import com.goodlifecoder.groupware.user.entity.UserSocialAccountEntity;
import com.goodlifecoder.groupware.user.entity.UserSocialAccountId;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.time.Duration;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 루트 가입. 확인 전에는 이메일만 보내고, 코드 확인 뒤에는 짧은 가입 토큰만 둔다.
 * 비밀번호나 같은 이메일의 소셜 연결에서 회원 행을 만든다. 테넌트는 만들지 않는다.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RootSignupService {

    private final UserRepository userRepository;
    private final SocialAccountRepository socialAccountRepository;
    private final PasswordEncoder passwordEncoder;
    private final MailProperties mailProperties;
    private final SignupVerificationMailSender signupVerificationMailSender;
    private final SignupMailRateLimiter signupMailRateLimiter;
    private final SignupEmailCodeStore signupEmailCodeStore;
    private final RootSignupStore rootSignups;

    /** 이메일을 접수하고 확인 메일을 보낸다. 회원과 테넌트는 만들지 않는다. */
    public void request(String email, String clientIp) {
        String normalized = SignupService.normalizeEmail(email);
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
        if (userRepository.findByEmail(normalized).isPresent()) {
            rootSignups.deletePending(normalized);
            signupEmailCodeStore.revoke(Flow.ROOT, normalized);
            throw new EmailAlreadyUsedException();
        }
        Duration ttl = rootSignups.remaining(normalized).orElse(PendingSignupStore.RETENTION);
        boolean replace = rootSignups.findPending(normalized).isPresent();
        rootSignups.savePending(normalized, ttl);
        send(normalized, replace);
    }

    /** 기다리는 이메일이 있으면 확인 메일을 다시 보낸다. 없으면 그대로 끝낸다. */
    public void resend(String email, String clientIp) {
        String normalized = SignupService.normalizeEmail(email);
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
        if (rootSignups.findPending(normalized).isEmpty()) {
            return;
        }
        send(normalized, true);
    }

    /** 토큰이 맞으면 짧은 가입 토큰을 준다. 회원은 만들지 않는다. 5회를 넘기면 TooManyAttemptsException. */
    public String confirmEmail(String email, String code) {
        String normalized = SignupService.normalizeEmail(email);
        String submitted = code == null ? "" : code.trim();
        Status status = signupEmailCodeStore.check(Flow.ROOT, normalized, submitted);
        if (status == Status.EXHAUSTED) {
            throw new TooManyAttemptsException();
        }
        if (status != Status.MATCH) {
            throw new InvalidSignupTokenException();
        }
        String pending = rootSignups.findPending(normalized).orElseThrow(InvalidSignupTokenException::new);
        rootSignups.deletePending(pending);
        if (userRepository.findByEmail(pending).isPresent()) {
            throw new InvalidSignupTokenException();
        }
        return rootSignups.issueVerified(pending);
    }

    /** 60초 재발송 간격은 메일 횟수 한도보다 먼저 본다. */
    private void ensureSendable(String email) {
        if (signupEmailCodeStore.coolingDown(Flow.ROOT, email)) {
            throw new TooManyRequestsException();
        }
    }

    /** 확인된 이메일에 비밀번호를 붙여 회원을 만든다. */
    @Transactional
    public void completeWithPassword(String signupToken, String password) {
        if (password == null || password.isBlank()) {
            throw new InvalidSignupException();
        }
        String email = rootSignups.findVerified(signupToken).orElseThrow(InvalidSignupTokenException::new);
        if (userRepository.findByEmail(email).isPresent()) {
            rootSignups.deleteVerified(signupToken);
            throw new EmailAlreadyUsedException();
        }
        try {
            userRepository.saveAndFlush(UserEntity.builder()
                    .email(email)
                    .password(passwordEncoder.encode(password))
                    .enabled(true)
                    .build());
        } catch (DataIntegrityViolationException ex) {
            rootSignups.deleteVerified(signupToken);
            throw new EmailAlreadyUsedException();
        }
        rootSignups.deleteVerified(signupToken);
    }

    /**
     * 확인된 이메일과 같은 소셜 계정으로 회원을 만든다.
     * 그 이메일의 회원이 이미 있으면 소셜 연결만 붙인다.
     */
    @Transactional
    public UserEntity completeWithSocial(
            String signupToken,
            String providerEmail,
            String name,
            UserSocialAccountId socialId
    ) {
        String email = rootSignups.findVerified(signupToken).orElseThrow(InvalidSignupTokenException::new);
        String socialEmail = SignupService.normalizeEmail(providerEmail);
        if (!email.equals(socialEmail)) {
            throw new InvalidSignupException();
        }
        Optional<UserSocialAccountEntity> linked = socialAccountRepository.findById(socialId);
        if (linked.isPresent()) {
            UserEntity owner = linked.get().getUser();
            if (!email.equals(SignupService.normalizeEmail(owner.getEmail()))) {
                throw new EmailAlreadyUsedException();
            }
            rootSignups.deleteVerified(signupToken);
            return owner;
        }
        UserEntity user = userRepository.findByEmail(email).orElseGet(() -> userRepository.save(UserEntity.builder()
                .email(email)
                .nickname(name)
                .enabled(true)
                .build()));
        socialAccountRepository.save(UserSocialAccountEntity.builder()
                .id(socialId)
                .user(user)
                .build());
        rootSignups.deleteVerified(signupToken);
        return user;
    }

    /** 확인 코드를 보낸다. 첫 발송이 실패하면 대기를 지우고, 다시 보내기 실패면 대기는 남긴다. 성공한 뒤에만 60초를 센다. */
    private void send(String email, boolean keepPendingOnFailure) {
        String code = signupEmailCodeStore.issue(Flow.ROOT, email);
        try {
            signupVerificationMailSender.send(email, code);
        } catch (RuntimeException ex) {
            signupEmailCodeStore.revoke(Flow.ROOT, email);
            if (!keepPendingOnFailure) {
                rootSignups.deletePending(email);
            }
            log.warn("루트 가입 확인 메일 발송 실패. to={}", email);
            throw new MailSendException();
        }
        signupEmailCodeStore.rememberSend(Flow.ROOT, email);
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
}
