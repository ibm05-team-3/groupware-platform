package com.goodlifecoder.groupware.user.controller;

import com.goodlifecoder.groupware.security.http.CurrentSessionUser;
import com.goodlifecoder.groupware.user.dto.ProfileResponse;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.mock.ResidenceMock;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * 프로필 조회. 닉네임과 입주 정보 자리표시자를 돌려준다.
 *
 * @author 조휘재
 * 작성일: 2026-11-02
 */
@RestController
@RequiredArgsConstructor
public class ProfileController {

    private final CurrentSessionUser currentSessionUser;
    private final UserRepository userRepository;

    /** 현재 세션 회원의 프로필. 세션이 없으면 401. */
    @GetMapping("/user/profile")
    public ResponseEntity<ProfileResponse> profile(HttpServletRequest request) {
        return currentSessionUser.id(request)
                .flatMap(userRepository::findById)
                .map(user -> ResponseEntity.ok(toResponse(user)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    /** 다른 회원 프로필. 본인만 볼 수 있다. */
    @GetMapping("/user/profile/{userId}")
    public ResponseEntity<ProfileResponse> profileOf(@PathVariable UUID userId, HttpServletRequest request) {
        return currentSessionUser.id(request)
                .flatMap(userRepository::findById)
                .map(viewer -> profileOf(viewer, userId))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    /** 본인이 아니면 403. 없으면 404. */
    private ResponseEntity<ProfileResponse> profileOf(UserEntity viewer, UUID userId) {
        if (!viewer.getId().equals(userId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return userRepository.findById(userId)
                .map(user -> ResponseEntity.ok(toResponse(user)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** 닉네임과 입주 자리표시자로 응답을 만든다. */
    private static ProfileResponse toResponse(UserEntity user) {
        return new ProfileResponse(blankToNull(user.getNickname()), ResidenceMock.placeholder());
    }

    /** 빈 닉네임은 JSON 에서 빠지도록 null 로 바꾼다. */
    private static String blankToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }
}
