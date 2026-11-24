package com.goodlifecoder.groupware.tenant.repository;

import com.goodlifecoder.groupware.tenant.entity.UserTenantMembershipEntity;
import com.goodlifecoder.groupware.tenant.entity.UserTenantMembershipId;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * 테넌트 소속. 루트 여부는 이 행에 있다.
 */
public interface UserTenantMembershipRepository extends JpaRepository<UserTenantMembershipEntity, UserTenantMembershipId> {

    /** 회원과 테넌트 한 쌍의 소속. 없으면 비운다. */
    Optional<UserTenantMembershipEntity> findByIdUserIdAndIdTenantId(UUID userId, UUID tenantId);
}
