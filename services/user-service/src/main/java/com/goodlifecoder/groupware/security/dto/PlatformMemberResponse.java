package com.goodlifecoder.groupware.security.dto;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/**
 * 본사 화면에 주는 회원 한 줄. 탈퇴하면 email 은 null 이다.
 *
 * @author 조휘재
 * 작성일: 2026-11-11
 */
public record PlatformMemberResponse(
        UUID id,
        String nickname,
        String email,
        List<String> roles,
        List<String> providers,
        boolean enabled,
        OffsetDateTime createdAt
) {
}
