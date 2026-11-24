package com.goodlifecoder.groupware.iam.repository;

import com.goodlifecoder.groupware.iam.entity.UserTenantRoleEntity;
import com.goodlifecoder.groupware.iam.entity.UserTenantRoleId;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * 한 테넌트 안에서 회원에게 붙은 TENANT 역할이다.
 */
public interface UserTenantRoleRepository extends JpaRepository<UserTenantRoleEntity, UserTenantRoleId> {

    /** 이 회원의 그 테넌트 역할과 권한을 함께 읽는다. */
    @Query("""
            select assignment
            from UserTenantRoleEntity assignment
            join fetch assignment.role
            where assignment.id.userId = :userId
              and assignment.id.tenantId = :tenantId
            """)
    List<UserTenantRoleEntity> findAllWithRoleByUserIdAndTenantId(
            @Param("userId") UUID userId,
            @Param("tenantId") UUID tenantId);
}
