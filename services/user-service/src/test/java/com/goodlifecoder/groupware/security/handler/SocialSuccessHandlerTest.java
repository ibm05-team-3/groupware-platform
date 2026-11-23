package com.goodlifecoder.groupware.security.handler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.goodlifecoder.groupware.common.config.AppProperties;
import com.goodlifecoder.groupware.security.http.SessionCookieFactory;
import com.goodlifecoder.groupware.security.oauth.LoginEntranceOAuth;
import com.goodlifecoder.groupware.security.oauth.SocialReturnPath;
import com.goodlifecoder.groupware.security.service.AuthService;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

class SocialSuccessHandlerTest {

    private final AuthService authService = mock(AuthService.class);
    private final SessionCookieFactory cookies = mock(SessionCookieFactory.class);
    private final SocialSuccessHandler handler = new SocialSuccessHandler(
            authService,
            new AppProperties(new AppProperties.Frontend("https://app.example"), null),
            cookies
    );

    @Test
    void platformSocialIssuesAHeadquartersSession() throws Exception {
        when(authService.openPlatformSession("user-1")).thenReturn(Optional.of("sid"));
        when(cookies.write("sid")).thenReturn(ResponseCookie.from("session", "sid").build());
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(LoginEntranceOAuth.ATTRIBUTE, "PLATFORM");
        request.setAttribute(SocialReturnPath.ATTRIBUTE, "/hq");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication());

        verify(authService, never()).openSession("user-1");
        assertEquals("https://app.example/hq", response.getRedirectedUrl());
        assertTrue(response.getHeader(HttpHeaders.SET_COOKIE).contains("sid"));
    }

    @Test
    void platformSocialWithoutAHeadquartersRoleSetsNoCookie() throws Exception {
        when(authService.openPlatformSession("user-1")).thenReturn(Optional.empty());
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(LoginEntranceOAuth.ATTRIBUTE, "PLATFORM");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication());

        verify(cookies, never()).write(ArgumentMatchers.any());
        verify(authService, never()).openSession("user-1");
        assertEquals("https://app.example", response.getRedirectedUrl());
        assertNull(response.getHeader(HttpHeaders.SET_COOKIE));
    }

    @Test
    void memberSocialDoesNotIssueAHeadquartersSession() throws Exception {
        when(authService.openSession("user-1")).thenReturn("sid");
        when(cookies.write("sid")).thenReturn(ResponseCookie.from("session", "sid").build());
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, authentication());

        verify(authService, never()).openPlatformSession("user-1");
        assertEquals("https://app.example", response.getRedirectedUrl());
    }

    private static Authentication authentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn("user-1");
        return authentication;
    }
}
