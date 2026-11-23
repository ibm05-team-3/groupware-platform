package com.goodlifecoder.groupware.iam.entity;

import com.goodlifecoder.groupware.common.entity.BaseTimeEntity;
import com.goodlifecoder.groupware.tenant.entity.UserTenantMembershipEntity;
import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinColumns;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 테넌트 안 역할. 소속이 있는 회원만 가질 수 있고 scope 는 TENANT 다.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(
        name = "user_tenant_roles",
        indexes = @Index(name = "idx_user_tenant_roles_tenant", columnList = "tenant_id, user_id")
)
public class UserTenantRoleEntity extends BaseTimeEntity {

    @EmbeddedId
    private UserTenantRoleId id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumns({
            @JoinColumn(name = "user_id", referencedColumnName = "user_id", insertable = false, updatable = false),
            @JoinColumn(name = "tenant_id", referencedColumnName = "tenant_id", insertable = false, updatable = false)
    })
    private UserTenantMembershipEntity membership;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role", referencedColumnName = "code", insertable = false, updatable = false)
    private RoleEntity role;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private RoleScope scope = RoleScope.TENANT;
}
