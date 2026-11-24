package com.goodlifecoder.groupware.security.http;

import com.goodlifecoder.groupware.security.service.AuthService;
import com.goodlifecoder.groupware.security.session.LoginEntrance;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * 요청의 세션 쿠키에서 회원 id와 로그인 입구를 읽는다. 쿠키가 없거나 UUID가 아니면 비운다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@Component
@RequiredArgsConstructor
public class CurrentSessionUser {

    private final SessionCookieFactory sessionCookieFactory;
    private final AuthService authService;

    /** 세션 주체. 본사 로그인이면 entrance 가 PLATFORM 이다. */
    public record Principal(UUID userId, LoginEntrance entrance) {

        /** 이번 세션이 본사 로그인인지. 게이트웨이의 context platform 과 같다. */
        public boolean platform() {
            return entrance == LoginEntrance.PLATFORM;
        }
    }

    /** 세션 주체를 회원 id로 바꾼다. */
    public Optional<UUID> id(HttpServletRequest request) {
        return principal(request).map(Principal::userId);
    }

    /** 쿠키의 세션을 한 번 읽는다. */
    public Optional<Principal> principal(HttpServletRequest request) {
        return sessionCookieFactory.read(request)
                .flatMap(authService::findBrowserSession)
                .flatMap(session -> parse(session.sub()).map(id -> new Principal(id, session.entrance())));
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
