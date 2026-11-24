package com.goodlifecoder.groupware.user.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 소셜 연결의 기본 키. 한 제공자 계정은 한 행이다.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@Embeddable
public class UserSocialAccountId implements Serializable {

    @Enumerated(EnumType.STRING)
    @Column(name = "provider_type", nullable = false, length = 255)
    private SocialProviderType providerType;

    @Column(name = "provider_id", nullable = false, length = 255)
    private String providerId;
}
