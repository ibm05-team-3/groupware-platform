package com.goodlifecoder.groupware.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.goodlifecoder.groupware.security.http.CurrentSessionUser;
import com.goodlifecoder.groupware.security.http.CurrentSessionUser.Principal;
import com.goodlifecoder.groupware.security.session.LoginEntrance;
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
    private final SessionCookieAuthenticationFilter filter =
            new SessionCookieAuthenticationFilter(currentSessionUser);

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void missingSessionDoesNotAuthenticate() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/user/session");
        when(currentSessionUser.principal(request)).thenReturn(Optional.empty());

        filter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void sessionOnOtherPathHasNoPlatformAuthority() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/user/session");
        when(currentSessionUser.principal(request)).thenReturn(Optional.of(principal(LoginEntrance.PLATFORM)));

        filter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities()).isEmpty();
    }

    @Test
    void internalAccessSkipsSession() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/internal/session/access");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(chain).doFilter(request, response);
    }

    @Test
    void platformLoginSessionGetsPlatformAuthority() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/platform/members");
        when(currentSessionUser.principal(request)).thenReturn(Optional.of(principal(LoginEntrance.PLATFORM)));

        filter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
                .extracting(authority -> authority.getAuthority())
                .containsExactly(SessionCookieAuthenticationFilter.PLATFORM_AUTHORITY);
    }

    @Test
    void tenantSessionOnPlatformPathHasNoAuthority() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/platform/members");
        when(currentSessionUser.principal(request)).thenReturn(Optional.of(principal(LoginEntrance.TENANT)));

        filter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities()).isEmpty();
    }

    @Test
    void accountSessionOnPlatformPathHasNoAuthority() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/user-service/platform/session");
        request.setContextPath("/user-service");
        when(currentSessionUser.principal(request)).thenReturn(Optional.of(principal(null)));

        filter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities()).isEmpty();
    }

    private static Principal principal(LoginEntrance entrance) {
        return new Principal(USER_ID, entrance);
    }
}
