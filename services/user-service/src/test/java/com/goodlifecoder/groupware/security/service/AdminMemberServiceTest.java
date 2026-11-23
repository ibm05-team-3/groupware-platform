package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.dto.AdminMemberResponse;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AdminMemberServiceTest {

    private static final UUID ACTIVE = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID WITHDRAWN = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID UNVERIFIED = UUID.fromString("00000000-0000-0000-0000-000000000003");

    private final UserRepository users = mock(UserRepository.class);
    private final SocialAccountRepository social = mock(SocialAccountRepository.class);
    private final AdminMemberService service = new AdminMemberService(users, social);

    @Test
    void unverifiedSignupsAreNotListedAndWithdrawnUsersStay() {
        UserEntity active = UserEntity.builder()
                .id(ACTIVE).enabled(true).nickname("민수").email("active@test.com").password("{noop}x").build();
        UserEntity withdrawn = UserEntity.builder().id(WITHDRAWN).enabled(false).build();
        UserEntity unverified = UserEntity.builder()
                .id(UNVERIFIED).enabled(false).email("wait@test.com").password("{noop}x").build();
        when(users.findAllByOrderByCreatedAtDescIdDesc()).thenReturn(List.of(unverified, withdrawn, active));
        when(social.findUserIdsAndProviders()).thenReturn(List.of());

        List<AdminMemberResponse> members = service.list();

        assertThat(members).extracting(AdminMemberResponse::id).containsExactly(WITHDRAWN, ACTIVE);
        assertThat(members.get(0).enabled()).isFalse();
        assertThat(members.get(1).email()).isEqualTo("active@test.com");
    }
}
