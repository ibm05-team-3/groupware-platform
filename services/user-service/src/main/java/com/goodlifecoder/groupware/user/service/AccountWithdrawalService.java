package com.goodlifecoder.groupware.user.service;

import com.goodlifecoder.groupware.security.service.AuthService;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 개인정보처리방침의 탈퇴 파기.
 * 이메일, 비밀번호, 소셜 제공자 식별자, 닉네임은 탈퇴 시 지운다. 이메일과 비밀번호는 회원 행에서 비운다.
 * 법령상 계약·결제 기록은 contract-service에 있으므로 여기서 지우지 않는다.
 * users 행은 다른 서비스의 회원 id 참조를 위해 남기고 로그인만 막는다.
 *
 * @author 조휘재
 * 작성일: 2026-11-05
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
