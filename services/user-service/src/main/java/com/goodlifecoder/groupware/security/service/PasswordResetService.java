package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.common.config.MailProperties;
import com.goodlifecoder.groupware.security.dao.PasswordResetTokenDAO;
import com.goodlifecoder.groupware.security.mail.PasswordResetMailDispatcher;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 비밀번호 재설정.
 * 메일이 꺼져 있으면 계정을 조회하지 않는다.
 * 메일이 켜져 있으면 응답을 먼저 끝낸 뒤 링크를 그 메일함으로만 보낸다. 응답에는 토큰을 넣지 않는다.
 *
 * @author 조휘재
 * 작성일: 2026-11-11
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final MailProperties mailProperties;
    private final UserRepository userRepository;
    private final PasswordResetTokenDAO passwordResetTokenDAO;
    private final PasswordResetMailDispatcher passwordResetMailDispatcher;
    private final PasswordResetRateLimiter passwordResetRateLimiter;
    private final PasswordEncoder passwordEncoder;
    private final AuthService authService;

    /**
     * 재설정 메일을 예약한다.
     * 메일이 꺼져 있으면 조회하지 않는다. 없거나 횟수를 넘긴 이메일도 그냥 돌아온다.
     */
    public void requestReset(String email, String clientIp) {
        if (!mailProperties.enabled()) {
            throw new MailDisabledException();
        }
        String normalized = SignupService.normalizeEmail(email);
        if (!isEmail(normalized)) {
            throw new InvalidPasswordResetException();
        }
        if (!passwordResetRateLimiter.allow(normalized, clientIp)) {
            return;
        }
        Optional<UserEntity> account = userRepository.findByEmail(normalized);
        if (account.isEmpty()) {
            return;
        }
        UUID userId = account.get().getId();
        String token = passwordResetTokenDAO.issue(userId);
        try {
            passwordResetMailDispatcher.send(userId, normalized, mailProperties.resetUrl(token));
        } catch (RuntimeException ex) {
            passwordResetTokenDAO.revoke(userId);
            log.warn("비밀번호 재설정 메일 발송을 예약하지 못했습니다. to={}", normalized, ex);
        }
    }

    /** 토큰을 소비하고 비밀번호를 바꾼 뒤 그 회원의 세션을 모두 끊는다. */
    @Transactional
    public void confirm(String token, String password) {
        if (token == null || token.isBlank() || password == null || password.isBlank()) {
            throw new InvalidPasswordResetException();
        }
        UUID userId = passwordResetTokenDAO.consume(token).orElseThrow(InvalidPasswordResetTokenException::new);
        UserEntity account = userRepository.findById(userId)
                .filter(user -> user.getEmail() != null)
                .orElseThrow(InvalidPasswordResetTokenException::new);
        account.changePassword(passwordEncoder.encode(password));
        userRepository.save(account);
        authService.revokeUser(userId.toString(), null);
    }

    /** @ 와 도메인 점이 있는지만 본다. */
    private static boolean isEmail(String email) {
        int at = email.indexOf('@');
        return at > 0 && email.indexOf('.', at + 1) > at + 1 && !email.contains(" ");
    }

    /**
     * app.mail.enabled 가 꺼져 있을 때.
     *
     * @author 조휘재
     * 작성일: 2026-11-11
     */
    public static class MailDisabledException extends RuntimeException {
    }

    /**
     * 이메일이나 비밀번호 형식이 아닐 때.
     *
     * @author 조휘재
     * 작성일: 2026-11-11
     */
    public static class InvalidPasswordResetException extends RuntimeException {
    }

    /**
     * 토큰이 없거나 이미 썼을 때.
     *
     * @author 조휘재
     * 작성일: 2026-11-11
     */
    public static class InvalidPasswordResetTokenException extends RuntimeException {
    }
}
