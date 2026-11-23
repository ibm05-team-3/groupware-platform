package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.service.SignupService.EmailAlreadyUsedException;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * 확인된 가입을 활성 회원으로 저장한다.
 * 미인증 행 삭제는 별도 트랜잭션이라, 이어지는 저장이 실패해도 활성 회원을 되살리지 않는다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@Service
@RequiredArgsConstructor
public class SignupAccountWriter {

    private final UserRepository userRepository;
    private final UnverifiedUserDeleter unverifiedUserDeleter;
    private final ConfirmedAccountWriter confirmedAccountWriter;

    /** 활성 이메일이면 EmailAlreadyUsedException. 미인증 행은 지운 뒤 활성 회원을 만든다. */
    public void create(String email, String passwordHash) {
        Optional<UserEntity> existing = userRepository.findByEmail(email);
        if (existing.isPresent()) {
            if (existing.get().isEnabled()) {
                throw new EmailAlreadyUsedException();
            }
            unverifiedUserDeleter.deleteIfUnverified(existing.get().getId());
        }
        confirmedAccountWriter.insert(email, passwordHash);
    }
}
