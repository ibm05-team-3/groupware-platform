package com.goodlifecoder.groupware.user.entity;

import com.goodlifecoder.groupware.common.entity.BaseTimeEntity;
import jakarta.persistence.*;
import lombok.*;

/**
 * 소셜 로그인 연결. 기본 키는 제공자와 그 제공자가 준 id 이다.
 *
 * @author 조휘재
 * 작성일: 2026-10-16
 */
@ToString
@Entity
@Table(name = "user_social_accounts")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserSocialAccountEntity extends BaseTimeEntity {

    @EmbeddedId
    private UserSocialAccountId id;

    @ToString.Exclude
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;
}
