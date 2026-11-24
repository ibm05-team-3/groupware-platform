package com.goodlifecoder.groupware.tenant.entity;

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
 * 테넌트 소속. 루트 여부는 이 행에 있다.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user_tenant_memberships")
public class UserTenantMembershipEntity extends BaseTimeEntity {

    @EmbeddedId
    private UserTenantMembershipId id;

    @MapsId("userId")
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @MapsId("tenantId")
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private TenantEntity tenant;

    @Column(name = "is_root", nullable = false)
    @Builder.Default
    private boolean root = false;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private MembershipStatus status = MembershipStatus.ACTIVE;
}
