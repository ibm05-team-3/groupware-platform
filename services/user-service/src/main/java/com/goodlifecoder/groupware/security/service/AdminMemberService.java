package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.dto.AdminMemberResponse;
import com.goodlifecoder.groupware.user.entity.SocialProviderType;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 관리자 회원 목록. 확인 전 가입은 빼고 탈퇴는 남긴다.
 *
 * @author 조휘재
 * 작성일: 2026-11-11
 */
@Service
@RequiredArgsConstructor
public class AdminMemberService {

    private final UserRepository userRepository;
    private final SocialAccountRepository socialAccountRepository;

    /**
     * 확인 전 가입은 이메일이 남은 비활성 계정이다. 회원 목록에 넣지 않는다.
     * 탈퇴는 이메일을 지우므로 비활성으로 남긴다.
     */
    @Transactional(readOnly = true)
    public List<AdminMemberResponse> list() {
        Map<UUID, List<String>> providers = new HashMap<>();
        for (Object[] row : socialAccountRepository.findUserIdsAndProviders()) {
            UUID userId = (UUID) row[0];
            SocialProviderType provider = (SocialProviderType) row[1];
            providers.computeIfAbsent(userId, ignored -> new ArrayList<>()).add(provider.name());
        }
        return userRepository.findAllByOrderByCreatedAtDescIdDesc().stream()
                .filter(user -> user.isEnabled() || user.getEmail() == null)
                .map(user -> toResponse(user, providers))
                .toList();
    }

    /** 소셜 제공자를 이름순으로 담는다. 이메일이 없으면 null 이다. */
    private static AdminMemberResponse toResponse(UserEntity user, Map<UUID, List<String>> providers) {
        List<String> social = providers.getOrDefault(user.getId(), List.of()).stream().sorted().toList();
        return new AdminMemberResponse(
                user.getId(),
                user.getNickname(),
                user.getEmail(),
                List.of(),
                social,
                user.isEnabled(),
                user.getCreatedAt());
    }
}
