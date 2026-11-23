package com.goodlifecoder.groupware.security.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

class DoorAuthorizationRequestResolverTest {

    private static final String AUTHORIZATION_URI =
            "https://accounts.google.com/o/oauth2/v2/auth?state=state-1";

    @Test
    void platformStartTagsHeadquartersEntranceAndKeepsTheProviderRequest() {
        OAuth2AuthorizationRequest platformRequest = authorizationRequest("google");
        DoorAuthorizationRequestResolver resolver = new DoorAuthorizationRequestResolver(
                delegate(authorizationRequest("member")),
                delegate(platformRequest));
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET", "/user-service/platform/oauth2/authorization/google");
        request.setContextPath("/user-service");

        OAuth2AuthorizationRequest resolved = resolver.resolve(request);

        assertEquals("PLATFORM", resolved.getAttribute(LoginEntranceOAuth.ATTRIBUTE));
        assertEquals("google", resolved.getAttribute(OAuth2ParameterNames.REGISTRATION_ID));
        assertEquals(AUTHORIZATION_URI, resolved.getAuthorizationRequestUri());
    }

    @Test
    void memberStartDoesNotTagHeadquartersEntrance() {
        OAuth2AuthorizationRequest memberRequest = authorizationRequest("google");
        DoorAuthorizationRequestResolver resolver = new DoorAuthorizationRequestResolver(
                delegate(memberRequest),
                delegate(authorizationRequest("platform")));
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET", "/user/oauth2/authorization/google");

        assertSame(memberRequest, resolver.resolve(request));
        assertNull(memberRequest.getAttribute(LoginEntranceOAuth.ATTRIBUTE));
    }

    @Test
    void platformStartDoesNotFallBackToTheMemberResolver() {
        OAuth2AuthorizationRequest memberRequest = authorizationRequest("google");
        DoorAuthorizationRequestResolver resolver = new DoorAuthorizationRequestResolver(
                delegate(memberRequest),
                delegate(null));
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET", "/platform/oauth2/authorization/google");

        assertNull(resolver.resolve(request));
    }

    private static OAuth2AuthorizationRequest authorizationRequest(String registrationId) {
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .clientId("google-client")
                .redirectUri("http://localhost:8081/user-service/user/oauth2/code/google")
                .state("state-1")
                .attributes(Map.of(OAuth2ParameterNames.REGISTRATION_ID, registrationId))
                .authorizationRequestUri(AUTHORIZATION_URI)
                .build();
    }

    private static OAuth2AuthorizationRequestResolver delegate(OAuth2AuthorizationRequest authorizationRequest) {
        return new OAuth2AuthorizationRequestResolver() {
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                return authorizationRequest;
            }

            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
                return authorizationRequest;
            }
        };
    }
}
