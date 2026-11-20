package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import com.goodlifecoder.groupware.security.entity.CustomUserDetails;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 이메일 로그인과 세션 갱신에 쓰는 UserDetails 조회.
 *
 * @author 조휘재
 * 작성일: 2026-10-16
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService  implements UserDetailsService {

    private final UserRepository userRepository;

    /** 이메일로 회원을 찾는다. 없으면 로그인 실패와 같은 예외를 던진다. */
    @Override
    @Transactional(readOnly = true)
    public @NonNull UserDetails loadUserByUsername(String loginId) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByEmail(SignupService.normalizeEmail(loginId))
                .filter(found -> found.getPassword() != null)
                .orElseThrow(() -> new UsernameNotFoundException("이메일 또는 비밀번호가 올바르지 않습니다."));

        return new CustomUserDetails(user, user.getPassword());
    }

    /** 회원 번호로 계정을 읽는다. 소셜 전용 계정은 비밀번호가 null 이다. */
    @Transactional(readOnly = true)
    public UserDetails loadUserById(String accessSub) throws UsernameNotFoundException {
        long userId;
        try {
            userId = Long.parseLong(accessSub);
        } catch (NumberFormatException e) {
            throw new UsernameNotFoundException("아이디 혹은 비밀번호가 틀렸습니다.");
        }
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("아이디 혹은 비밀번호가 틀렸습니다."));

        return new CustomUserDetails(user, user.getPassword());
    }
}
