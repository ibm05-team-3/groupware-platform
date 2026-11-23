package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore.Flow;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * 확인하지 않은 가입 행만 지운다. 활성 회원과 탈퇴 회원은 그대로 둔다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@Service
@RequiredArgsConstructor
public class UnverifiedUserDeleter {

    private final SocialAccountRepository socialAccountRepository;
    private final UserRepository userRepository;
    private final SignupEmailCodeStore signupEmailCodeStore;

    /** 비활성 이메일 회원과 소셜 연결을 지운다. 활성 회원이거나 이메일이 없으면 회원 행은 남긴다. 별도 트랜잭션이다. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void deleteIfUnverified(UUID userId) {
        if (userId == null) {
            return;
        }
        Optional<UserEntity> found = userRepository.findById(userId);
        if (found.isEmpty() || found.get().getEmail() == null) {
            return;
        }
        UserEntity user = found.get();
        if (user.isEnabled()) {
            return;
        }
        socialAccountRepository.deleteByUserId(userId);
        userRepository.delete(user);
        userRepository.flush();
        signupEmailCodeStore.revoke(Flow.SIGNUP, user.getEmail());
    }
}
