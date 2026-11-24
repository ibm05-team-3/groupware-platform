package com.goodlifecoder.groupware.tenant.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 회원과 테넌트 한 쌍. 소속 행의 기본 키다.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@Embeddable
public class UserTenantMembershipId implements Serializable {

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "tenant_id")
    private UUID tenantId;
}
