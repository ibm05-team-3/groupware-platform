package com.goodlifecoder.groupware.security.controller;

import com.goodlifecoder.groupware.security.dto.AccessTokenResponse;
import com.goodlifecoder.groupware.security.dto.SessionResponseDTO;
import com.goodlifecoder.groupware.security.dto.TenantEntryRequestDTO;
import com.goodlifecoder.groupware.security.http.SessionCookieFactory;
import com.goodlifecoder.groupware.security.service.AuthService;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;
import java.util.UUID;

/**
 * 세션 확인, 로그아웃, 게이트웨이용 액세스 토큰 조회.
 * 로그인 본문은 LoginFilter 가 받는다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final SessionCookieFactory sessionCookieFactory;
    private final UserRepository userRepository;

    /** 세션 쿠키가 있으면 로그인 여부, 회원 번호, 닉네임을 돌려준다. 없으면 401. */
    @GetMapping("/user/session")
    public ResponseEntity<SessionResponseDTO> session(HttpServletRequest request) {
        return sessionCookieFactory.read(request)
                .flatMap(authService::sessionSubject)
                .flatMap(this::sessionResponse)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    /** 세션의 회원 id로 닉네임을 찾아 응답을 만든다. UUID가 아니면 비운다. */
    private Optional<SessionResponseDTO> sessionResponse(String userId) {
        return userId(userId)
                .flatMap(userRepository::findById)
                .map(user -> new SessionResponseDTO(true, userId, blankToNull(user.getNickname())));
    }

    /**
     * 본사 세션 확인. 맞으면 본문 없이 204.
     * 세션이 없으면 401, 본사 역할이 없으면 403 은 필터와 보안 설정이 돌려준다.
     */
    @GetMapping("/platform/session")
    public ResponseEntity<Void> adminSession() {
        return ResponseEntity.noContent().build();
    }

    /** 세션 주체의 회원 id. UUID가 아니면 비운다. */
    private static Optional<UUID> userId(String value) {
        try {
            return Optional.of(UUID.fromString(value));
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    /** 빈 닉네임은 JSON 에서 빠지도록 null 로 바꾼다. */
    private static String blankToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }

    /**
     * 세션의 토큰을 고른 회사 토큰으로 바꾼다.
     * 쿠키가 없거나 세션이 없으면 401, slug 가 비어 있으면 400, 활성 소속이 없으면 403.
     */
    @PostMapping("/user/tenant-entry")
    public ResponseEntity<Void> enterTenant(
            @RequestBody TenantEntryRequestDTO request,
            HttpServletRequest httpRequest
    ) {
        if (request.tenant() == null || request.tenant().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        Optional<String> sessionId = sessionCookieFactory.read(httpRequest);
        if (sessionId.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        Optional<Boolean> entered = authService.enterTenant(sessionId.get(), request.tenant());
        if (entered.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!entered.get()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.noContent().build();
    }

    /**
     * 회사 선택을 해제하고 account 토큰으로 바꾼다.
     * 쿠키가 없거나 세션이 없으면 401, 회사 안이 아니면 403.
     */
    @PostMapping("/user/tenant-exit")
    public ResponseEntity<Void> leaveTenant(HttpServletRequest httpRequest) {
        Optional<String> sessionId = sessionCookieFactory.read(httpRequest);
        if (sessionId.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        Optional<Boolean> left = authService.leaveTenant(sessionId.get());
        if (left.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!left.get()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.noContent().build();
    }

    /** 현재 세션만 지우고 세션 쿠키를 만료시킨다. 다른 기기의 세션은 남긴다. */
    @PostMapping("/user/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        sessionCookieFactory.read(request).ifPresent(authService::closeSession);
        response.addHeader(HttpHeaders.SET_COOKIE, sessionCookieFactory.clear().toString());
        return ResponseEntity.noContent().build();
    }

    /** 게이트웨이가 세션 쿠키를 액세스 토큰으로 바꿀 때 호출한다. 게이트웨이 라우트는 아니다. */
    @GetMapping("/internal/session/access")
    public ResponseEntity<AccessTokenResponse> accessToken(HttpServletRequest request) {
        return sessionCookieFactory.read(request)
                .flatMap(authService::currentAccessToken)
                .map(token -> ResponseEntity.ok(new AccessTokenResponse(token)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }
}
