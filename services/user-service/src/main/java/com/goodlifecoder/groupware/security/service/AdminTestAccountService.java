package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.dao.PendingSignupStore;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Flow;
import com.goodlifecoder.groupware.security.service.SignupService.EmailAlreadyUsedException;
import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupException;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * 관리자가 확인 메일 없이 바로 로그인되는 계정을 만든다.
 *
 * @author 조휘재
 * 작성일: 2026-11-11
 */
@Service
@RequiredArgsConstructor
public class AdminTestAccountService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PendingSignupStore pendingSignups;
    private final SignupEmailCodeStore signupEmailCodeStore;
    private final UnverifiedSignupCleanup unverifiedSignupCleanup;
    private final ConfirmedAccountWriter confirmedAccountWriter;

    /** 대기 가입과 미인증 행을 지우고 활성 계정을 만든다. 활성 이메일이면 EmailAlreadyUsedException. */
    public void create(String email, String password) {
        String normalized = SignupService.normalizeEmail(email);
        if (!isEmail(normalized) || password == null || password.isBlank()) {
            throw new InvalidSignupException();
        }
        pendingSignups.delete(normalized);
        signupEmailCodeStore.revoke(Flow.SIGNUP, normalized);
        Optional<UserEntity> existing = userRepository.findByEmail(normalized);
        if (existing.isPresent()) {
            if (existing.get().isEnabled()) {
                throw new EmailAlreadyUsedException();
            }
            unverifiedSignupCleanup.deleteUnverified(existing.get().getId());
        }
        confirmedAccountWriter.insert(normalized, passwordEncoder.encode(password));
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
