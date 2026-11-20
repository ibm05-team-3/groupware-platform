package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.service.SignupService.EmailAlreadyUsedException;
import com.goodlifecoder.groupware.user.entity.Role;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 이미 정리된 이메일로 활성 회원을 만든다.
 *
 * @author 조휘재
 * 작성일: 2026-11-11
 */
@Service
@RequiredArgsConstructor
public class ConfirmedAccountWriter {

    private final UserRepository userRepository;

    /** 활성 회원을 만든다. 이메일이 겹치면 EmailAlreadyUsedException. */
    @Transactional
    public void insert(String email, String passwordHash) {
        try {
            userRepository.saveAndFlush(UserEntity.builder()
                    .roles(Set.of(Role.defaultAccountRole()))
                    .enabled(true)
                    .email(email)
                    .password(passwordHash)
                    .build());
        } catch (DataIntegrityViolationException ex) {
            throw new EmailAlreadyUsedException();
        }
    }
}
