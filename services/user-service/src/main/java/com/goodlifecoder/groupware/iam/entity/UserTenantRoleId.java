package com.goodlifecoder.groupware.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 테넌트 역할 행의 기본 키.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@Embeddable
public class UserTenantRoleId implements Serializable {

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "tenant_id")
    private UUID tenantId;

    @Column(name = "role", length = 50)
    private String role;
}
