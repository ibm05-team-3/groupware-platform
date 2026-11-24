package com.goodlifecoder.groupware.security.service;

import com.goodlifecoder.groupware.iam.repository.UserTenantRoleRepository;
import com.goodlifecoder.groupware.security.jwt.AccessTokenClaims;
import com.goodlifecoder.groupware.tenant.entity.MembershipStatus;
import com.goodlifecoder.groupware.tenant.entity.TenantEntity;
import com.goodlifecoder.groupware.tenant.entity.TenantStatus;
import com.goodlifecoder.groupware.tenant.entity.UserTenantMembershipEntity;
import com.goodlifecoder.groupware.tenant.repository.TenantRepository;
import com.goodlifecoder.groupware.tenant.repository.UserTenantMembershipRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

/**
 * 테넌트 로그인 토큰에 넣을 그 테넌트의 권한.
 * 본사 권한은 복사하지 않는다.
 */
@Service
@RequiredArgsConstructor
public class LoginTokenService {

    private final TenantRepository tenants;
    private final UserTenantMembershipRepository memberships;
    private final UserTenantRoleRepository tenantRoles;

    /** slug 의 활성 소속이 있으면 그 테넌트 토큰 클레임. 없으면 비운다. */
    public Optional<AccessTokenClaims> tenantClaims(UUID userId, String slug) {
        if (slug == null || slug.isBlank()) {
            return Optional.empty();
        }
        return tenants.findBySlug(slug.trim()).flatMap(tenant -> tenantClaims(userId, tenant.getId()));
    }

    /** 테넌트 번호의 활성 소속이 있으면 그 테넌트 토큰 클레임. 없으면 비운다. */
    public Optional<AccessTokenClaims> tenantClaims(UUID userId, UUID tenantId) {
        if (tenantId == null) {
            return Optional.empty();
        }
        Optional<TenantEntity> tenant = tenants.findById(tenantId);
        if (tenant.isEmpty() || tenant.get().getStatus() != TenantStatus.ACTIVE) {
            return Optional.empty();
        }
        Optional<UserTenantMembershipEntity> membership = memberships.findByIdUserIdAndIdTenantId(userId, tenantId);
        if (membership.isEmpty() || membership.get().getStatus() != MembershipStatus.ACTIVE) {
            return Optional.empty();
        }
        return Optional.of(AccessTokenClaims.tenant(
                tenantId,
                tenantRoles.findAllWithRoleByUserIdAndTenantId(userId, tenantId)));
    }
}
