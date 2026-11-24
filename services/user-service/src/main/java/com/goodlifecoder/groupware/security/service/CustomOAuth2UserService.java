package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.security.oauth.RootSignupOAuth;
import com.goodlifecoder.groupware.security.service.SignupService.EmailAlreadyUsedException;
import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupException;
import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupTokenException;
import com.goodlifecoder.groupware.user.entity.SocialProviderType;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import com.goodlifecoder.groupware.user.entity.UserSocialAccountEntity;
import com.goodlifecoder.groupware.user.entity.UserSocialAccountId;
import com.goodlifecoder.groupware.user.repository.SocialAccountRepository;
import com.goodlifecoder.groupware.user.repository.UserRepository;
import com.goodlifecoder.groupware.security.entity.CustomOAuth2User;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

/**
 * 네이버 로그인과, OIDC 가 넘긴 프로필을 로컬 회원에 연결한다.
 * 처음이면 회원과 소셜 계정을 저장한다.
 * 이미 연결된 계정은 이후 로그인에서 프로필을 덮어쓰지 않는다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final SocialAccountRepository socialAccountRepository;
    private final UserRepository userRepository;
    private final RootSignupService rootSignupService;

    /** 네이버는 response 객체를, 구글 속성은 맵 그대로 쓴다. 그 외 제공자는 거부한다. */
    @Override
    @Transactional
    public OAuth2User loadUser(@NonNull OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        Map<String, Object> attributes;
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        if (SocialProviderType.NAVER.name().equalsIgnoreCase(registrationId)) {
            attributes = responseAttributes(oAuth2User);
        } else if (SocialProviderType.GOOGLE.name().equalsIgnoreCase(registrationId)) {
            attributes = oAuth2User.getAttributes();
        } else {
            throw new OAuth2AuthenticationException("지원하지 않은 소셜 로그인입니다.");
        }
        return loadLinkedUser(registrationId, attributes);
    }

    /** 제공자와 제공자 id 로 소셜 계정을 찾거나 만든다. */
    @Transactional
    public CustomOAuth2User loadLinkedUser(String registrationId, Map<String, Object> attributes) {
        SocialProviderType registration;
        String providerId;
        String registrationName = registrationId.toUpperCase();
        if (SocialProviderType.NAVER.name().equals(registrationName)) {
            registration = SocialProviderType.NAVER;
            providerId = requiredText(attributes, "id");
        } else if (SocialProviderType.GOOGLE.name().equals(registrationName)) {
            registration = SocialProviderType.GOOGLE;
            providerId = requiredText(attributes, "sub");
        } else {
            throw new OAuth2AuthenticationException("지원하지 않은 소셜 로그인입니다.");
        }

        UserSocialAccountId socialId = new UserSocialAccountId(registration, providerId);
        String rootSignupToken = RootSignupOAuth.currentToken();
        if (rootSignupToken != null) {
            return completeRootSignup(rootSignupToken, attributes, socialId);
        }
        return socialAccountRepository.findById(socialId)
                .map(account -> new CustomOAuth2User(attributes, account.getUser()))
                .orElseGet(() -> createSocialUser(socialId, attributes));
    }

    /** 확인된 루트 가입 이메일과 같은 소셜 계정이면 회원을 만들거나 연결한다. */
    private CustomOAuth2User completeRootSignup(
            String signupToken,
            Map<String, Object> attributes,
            UserSocialAccountId socialId
    ) {
        String providerEmail = optionalText(attributes, "email").orElse(null);
        String name = optionalText(attributes, "name").orElse(null);
        try {
            UserEntity user = rootSignupService.completeWithSocial(
                    signupToken, providerEmail, name, socialId);
            return new CustomOAuth2User(attributes, user);
        } catch (InvalidSignupTokenException ex) {
            throw new OAuth2AuthenticationException("루트 가입 토큰이 없거나 만료됐습니다.");
        } catch (InvalidSignupException ex) {
            throw new OAuth2AuthenticationException("소셜 계정 이메일이 확인된 이메일과 다릅니다.");
        } catch (EmailAlreadyUsedException ex) {
            throw new OAuth2AuthenticationException("소셜 계정이 다른 회원에 연결되어 있습니다.");
        }
    }

    /** 소셜 첫 가입. 제공자 이름은 닉네임으로 둔다. */
    private CustomOAuth2User createSocialUser(UserSocialAccountId socialId, Map<String, Object> attributes) {
        String name = optionalText(attributes, "name").orElse(null);
        UserEntity user = userRepository.save(UserEntity.builder()
                .nickname(name)
                .build());
        socialAccountRepository.save(UserSocialAccountEntity.builder()
                .id(socialId)
                .user(user)
                .build());
        return new CustomOAuth2User(attributes, user);
    }

    /** 네이버 userinfo 의 response 맵. 없으면 로그인 실패다. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> responseAttributes(OAuth2User oAuth2User) {
        Object response = oAuth2User.getAttributes().get("response");
        if (!(response instanceof Map<?, ?> attributes)) {
            throw new OAuth2AuthenticationException("네이버 프로필이 없습니다.");
        }
        return (Map<String, Object>) attributes;
    }

    /** 비어 있지 않은 문자열만 고른다. */
    private static Optional<String> optionalText(Map<String, Object> attributes, String key) {
        Object value = attributes.get(key);
        if (value instanceof String text && !text.isBlank()) {
            return Optional.of(text);
        }
        return Optional.empty();
    }

    /** 제공자 식별자. 없으면 로그인 실패다. */
    private static String requiredText(Map<String, Object> attributes, String key) {
        Object value = attributes.get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new OAuth2AuthenticationException("소셜 프로필 식별자가 없습니다.");
        }
        return text;
    }
}