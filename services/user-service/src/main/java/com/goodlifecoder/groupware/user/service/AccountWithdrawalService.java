package com.goodlifecoder.groupware.user.service;

import com.goodlifecoder.groupware.security.service.AuthService;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 탈퇴. 닉네임, 이메일, 비밀번호, 소셜 연결을 지우고 세션을 끊는다.
 * users 행은 다른 서비스의 회원 id 참조를 위해 남기고 로그인만 막는다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@Service
@RequiredArgsConstructor
public class AccountWithdrawalService {

    private final UserRepository userRepository;
    private final SocialAccountRepository socialAccountRepository;
    private final AuthService authService;

    /**
     * 이메일 계정, 소셜 연결, 닉네임을 지우고 세션을 끊는다.
     * users 행은 남긴다.
     */
    @Transactional
    public void withdraw(UserEntity user, String currentSessionId) {
        user.withdraw();
        userRepository.saveAndFlush(user);
        socialAccountRepository.deleteByUserId(user.getId());
        authService.revokeUser(String.valueOf(user.getId()), currentSessionId);
    }
}
