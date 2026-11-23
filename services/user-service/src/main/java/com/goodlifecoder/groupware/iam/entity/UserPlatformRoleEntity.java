package com.goodlifecoder.groupware.iam.entity;

import com.goodlifecoder.groupware.common.entity.BaseTimeEntity;
import com.goodlifecoder.groupware.user.entity.UserEntity;
import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 본사 역할. scope 는 PLATFORM 만 허용한다.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user_platform_roles")
public class UserPlatformRoleEntity extends BaseTimeEntity {

    @EmbeddedId
    private UserPlatformRoleId id;

    @MapsId("userId")
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @MapsId("role")
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role", nullable = false)
    private RoleEntity role;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private RoleScope scope = RoleScope.PLATFORM;
}
