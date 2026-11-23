package com.goodlifecoder.groupware.security.http;

import com.goodlifecoder.groupware.security.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * 요청의 세션 쿠키에서 회원 id를 읽는다. 쿠키가 없거나 UUID가 아니면 비운다.
 *
 * @author 조휘재
 * 작성일: 2026-11-01
 */
@Component
@RequiredArgsConstructor
public class CurrentSessionUser {

    private final SessionCookieFactory sessionCookieFactory;
    private final AuthService authService;

    /** 세션 주체를 회원 id로 바꾼다. */
    public Optional<UUID> id(HttpServletRequest request) {
        return sessionCookieFactory.read(request)
                .flatMap(authService::sessionSubject)
                .flatMap(CurrentSessionUser::parse);
    }

    /** UUID가 아니면 비운다. */
    private static Optional<UUID> parse(String userId) {
        try {
            return Optional.of(UUID.fromString(userId));
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }
}
