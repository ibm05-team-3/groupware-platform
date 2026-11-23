package com.goodlifecoder.groupware.iam.entity;

import com.goodlifecoder.groupware.common.entity.BaseTimeEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * 역할 목록. 루트는 행으로 두지 않고 멤버십의 is_root 에 둔다.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(
        name = "roles",
        uniqueConstraints = @UniqueConstraint(name = "uk_roles_code_scope", columnNames = {"code", "scope"})
)
public class RoleEntity extends BaseTimeEntity {

    @Id
    @Column(length = 50)
    private String code;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private RoleScope scope;

    /** 서비스:API. 와일드카드는 그 서비스 안에서만 쓴다. */
    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(nullable = false, columnDefinition = "text[]")
    private String[] permissions;
}
