package com.goodlifecoder.groupware.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.goodlifecoder.groupware.iam.repository.UserPlatformRoleRepository;
import com.goodlifecoder.groupware.security.http.CurrentSessionUser;
import jakarta.servlet.FilterChain;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

class SessionCookieAuthenticationFilterTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");

    private final CurrentSessionUser currentSessionUser = mock(CurrentSessionUser.class);
    private final UserPlatformRoleRepository platformRoles = mock(UserPlatformRoleRepository.class);
    private final SessionCookieAuthenticationFilter filter =
            new SessionCookieAuthenticationFilter(currentSessionUser, platformRoles);

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void missingSessionDoesNotAuthenticate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/user/session");
        when(currentSessionUser.id(request)).thenReturn(Optional.empty());

        filter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(platformRoles);
    }

    @Test
    void sessionOnOtherPathDoesNotLookUpPlatformRole() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/user/session");
        when(currentSessionUser.id(request)).thenReturn(Optional.of(USER_ID));

        filter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities()).isEmpty();
        verifyNoInteractions(platformRoles);
    }

    @Test
    void internalAccessSkipsSessionAndPlatformRole() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/internal/session/access");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(currentSessionUser, platformRoles);
        verify(chain).doFilter(request, response);
    }

    @Test
    void platformPathUnderContextPathLooksUpRole() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/user-service/platform/session");
        request.setContextPath("/user-service");
        when(currentSessionUser.id(request)).thenReturn(Optional.of(USER_ID));
        when(platformRoles.existsByIdUserId(USER_ID)).thenReturn(true);

        filter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
                .extracting(authority -> authority.getAuthority())
                .containsExactly(SessionCookieAuthenticationFilter.PLATFORM_AUTHORITY);
    }

    @Test
    void platformPathWithoutRoleHasNoAuthority() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/platform/session");
        when(currentSessionUser.id(request)).thenReturn(Optional.of(USER_ID));
        when(platformRoles.existsByIdUserId(USER_ID)).thenReturn(false);

        filter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities()).isEmpty();
    }

    @Test
    void platformPathWithRoleGetsPlatformAuthority() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/platform/members");
        when(currentSessionUser.id(request)).thenReturn(Optional.of(USER_ID));
        when(platformRoles.existsByIdUserId(USER_ID)).thenReturn(true);

        filter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
                .extracting(authority -> authority.getAuthority())
                .containsExactly(SessionCookieAuthenticationFilter.PLATFORM_AUTHORITY);
    }
}
