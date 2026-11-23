package com.goodlifecoder.groupware.user.config;

import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * dev 프로파일에서만 로컬 계정 admin@naver.com 이 없으면 한 번 넣는다. 비밀번호는 12341234.
 *
 * @author 조휘재
 * 작성일: 2026-10-16
 */
@Profile("dev")
@Component
public class InitialDataLoader implements CommandLineRunner {
    private final UserRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    /** 시드에 필요한 저장소와 비밀번호 인코더를 받는다. */
    public InitialDataLoader(UserRepository memberRepository, PasswordEncoder passwordEncoder) {
        this.memberRepository = memberRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /** 이미 있으면 아무것도 하지 않는다. */
    @Override
    public void run(String... args) {
        if (memberRepository.findByEmail("admin@naver.com").isPresent()) {
            return;
        }
        memberRepository.save(UserEntity.builder()
                .email("admin@naver.com")
                .password(passwordEncoder.encode("12341234"))
                .build());
    }
}
