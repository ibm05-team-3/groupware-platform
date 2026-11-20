package com.goodlifecoder.groupware.security.config;

import com.goodlifecoder.groupware.security.filter.LoginFilter;
import com.goodlifecoder.groupware.security.filter.SessionCookieAuthenticationFilter;
import com.goodlifecoder.groupware.security.handler.LoginSuccessHandler;
import com.goodlifecoder.groupware.security.http.CurrentSessionUser;
import com.goodlifecoder.groupware.security.http.SessionCookieFactory;
import com.goodlifecoder.groupware.security.oauth.RedisOAuth2AuthorizationRequestRepository;
import com.goodlifecoder.groupware.security.oauth.ReturnToAuthorizationRequestResolver;
import com.goodlifecoder.groupware.security.service.AuthService;
import com.goodlifecoder.groupware.security.service.CustomOAuth2UserService;
import com.goodlifecoder.groupware.security.service.CustomOidcUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 이메일 로그인과 소셜 로그인 필터 체인.
 * 세션은 STATELESS 이고 CSRF, 폼 로그인, HTTP Basic 은 끈다.
 * 아래에 적은 공개 주소만 통과하고, 나머지는 세션 쿠키가 있어야 한다.
 *
 * @author 조휘재
 * 작성일: 2026-10-16
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private static final String LOGIN_URL = "/user/login";
    private static final String OAUTH_AUTHORIZATION_BASE_URI = "/user/oauth2/authorization";
    private static final String OAUTH_CALLBACK_URI = "/user/oauth2/code/*";

    private final AuthenticationSuccessHandler socialSuccessHandler;
    private final AuthenticationFailureHandler socialFailureHandler;

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOidcUserService customOidcUserService;
    private final AuthService authService;
    private final SessionCookieFactory sessionCookieFactory;
    private final CurrentSessionUser currentSessionUser;
    private final RedisOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    /** 이메일 비밀번호 해시. DelegatingPasswordEncoder 를 쓴다. */
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /** 이메일 로그인 필터가 쓸 인증 매니저. */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /** 소셜 인가 요청. PKCE 를 붙이고 return_to 를 보관한다. */
    @Bean
    OAuth2AuthorizationRequestResolver authorizationRequestResolver(ClientRegistrationRepository registrations) {
        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(registrations, OAUTH_AUTHORIZATION_BASE_URI);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return new ReturnToAuthorizationRequestResolver(resolver);
    }

    /** 이메일 로그인 필터와 네이버·구글 로그인을 한 체인에 묶는다. */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           AuthenticationManager authenticationManager,
                                           OAuth2AuthorizationRequestResolver authorizationRequestResolver) throws Exception {

        // 로그인 필터
        LoginFilter loginFilter = new LoginFilter(authenticationManager, LOGIN_URL);
        loginFilter.setAuthenticationSuccessHandler(new LoginSuccessHandler(authService, sessionCookieFactory));

        // http 설정
        http
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/user/login",
                                "/user/signup",
                                "/user/signup/email-verification",
                                "/user/signup/email-verification/resend",
                                "/user/root-signup",
                                "/user/root-signup/email-verification",
                                "/user/root-signup/email-verification/resend",
                                "/user/root-signup/password",
                                "/user/password-reset",
                                "/user/password-reset/confirm",
                                "/user/oauth2/authorization/**",
                                "/user/oauth2/code/**",
                                "/user/logout",
                                "/internal/session/access"
                        ).permitAll()
                        .requestMatchers(
                                "/actuator/health",
                                "/actuator/health/**",
                                "/actuator/prometheus"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint(
                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)
                ))
                .oauth2Login(oauth -> oauth
                        .authorizationEndpoint(endpoint -> endpoint
                                .authorizationRequestResolver(authorizationRequestResolver)
                                .authorizationRequestRepository(authorizationRequestRepository)
                        )
                        .redirectionEndpoint(endpoint -> endpoint.baseUri(OAUTH_CALLBACK_URI))
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService)
                                .oidcUserService(customOidcUserService)
                        )
                        .successHandler(socialSuccessHandler)
                        .failureHandler(socialFailureHandler)
                )
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(
                        new SessionCookieAuthenticationFilter(currentSessionUser),
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }
}