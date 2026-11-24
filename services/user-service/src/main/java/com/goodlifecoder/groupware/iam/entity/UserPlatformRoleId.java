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
 * 본사 역할 행의 기본 키. 테넌트는 없다.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@Embeddable
public class UserPlatformRoleId implements Serializable {

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "role", length = 50)
    private String role;
}
