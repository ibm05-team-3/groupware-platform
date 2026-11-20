package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.dto.AdminMemberResponse;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AdminMemberServiceTest {

    private final UserRepository users = mock(UserRepository.class);
    private final SocialAccountRepository social = mock(SocialAccountRepository.class);
    private final AdminMemberService service = new AdminMemberService(users, social);

    @Test
    void unverifiedSignupsAreNotListedAndWithdrawnUsersStay() {
        UserEntity active = UserEntity.builder()
                .id(1L).enabled(true).nickname("민수").email("active@test.com").password("{noop}x").build();
        UserEntity withdrawn = UserEntity.builder().id(2L).enabled(false).build();
        UserEntity unverified = UserEntity.builder()
                .id(3L).enabled(false).email("wait@test.com").password("{noop}x").build();
        when(users.findAllByOrderByIdDesc()).thenReturn(List.of(unverified, withdrawn, active));
        when(social.findUserIdsAndProviders()).thenReturn(List.of());

        List<AdminMemberResponse> members = service.list();

        assertThat(members).extracting(AdminMemberResponse::id).containsExactly(2L, 1L);
        assertThat(members.get(0).enabled()).isFalse();
        assertThat(members.get(1).email()).isEqualTo("active@test.com");
    }
}
