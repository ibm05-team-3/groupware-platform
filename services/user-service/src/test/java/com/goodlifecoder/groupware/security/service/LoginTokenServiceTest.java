package com.goodlifecoder.groupware.security.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.goodlifecoder.groupware.iam.entity.RoleEntity;
import com.goodlifecoder.groupware.iam.entity.RoleScope;
import com.goodlifecoder.groupware.iam.entity.UserTenantRoleEntity;
import com.goodlifecoder.groupware.iam.entity.UserTenantRoleId;
import com.goodlifecoder.groupware.iam.repository.UserTenantRoleRepository;
import com.goodlifecoder.groupware.security.jwt.AccessTokenClaims;
import com.goodlifecoder.groupware.tenant.entity.MembershipStatus;
import com.goodlifecoder.groupware.tenant.entity.TenantEntity;
import com.goodlifecoder.groupware.tenant.entity.TenantStatus;
import com.goodlifecoder.groupware.tenant.entity.UserTenantMembershipEntity;
import com.goodlifecoder.groupware.tenant.entity.UserTenantMembershipId;
import com.goodlifecoder.groupware.tenant.repository.TenantRepository;
import com.goodlifecoder.groupware.tenant.repository.UserTenantMembershipRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class LoginTokenServiceTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID TENANT_ID = UUID.fromString("00000000-0000-0000-0000-000000000010");

    private final TenantRepository tenants = mock(TenantRepository.class);
    private final UserTenantMembershipRepository memberships = mock(UserTenantMembershipRepository.class);
    private final UserTenantRoleRepository tenantRoles = mock(UserTenantRoleRepository.class);
    private final LoginTokenService loginTokens = new LoginTokenService(tenants, memberships, tenantRoles);

    @Test
    void blankSlugIssuesNothing() {
        assertThat(loginTokens.tenantClaims(USER_ID, "  ")).isEmpty();

        verify(tenants, never()).findBySlug(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void unknownSlugIssuesNothing() {
        when(tenants.findBySlug("acme")).thenReturn(Optional.empty());

        assertThat(loginTokens.tenantClaims(USER_ID, " acme ")).isEmpty();
    }

    @Test
    void suspendedTenantIssuesNothing() {
        when(tenants.findById(TENANT_ID)).thenReturn(Optional.of(tenant(TenantStatus.SUSPENDED)));

        assertThat(loginTokens.tenantClaims(USER_ID, TENANT_ID)).isEmpty();

        verify(memberships, never()).findByIdUserIdAndIdTenantId(USER_ID, TENANT_ID);
    }

    @Test
    void suspendedMembershipIssuesNothing() {
        when(tenants.findById(TENANT_ID)).thenReturn(Optional.of(tenant(TenantStatus.ACTIVE)));
        when(memberships.findByIdUserIdAndIdTenantId(USER_ID, TENANT_ID))
                .thenReturn(Optional.of(membership(false, MembershipStatus.SUSPENDED)));

        assertThat(loginTokens.tenantClaims(USER_ID, TENANT_ID)).isEmpty();

        verify(tenantRoles, never()).findAllWithRoleByUserIdAndTenantId(USER_ID, TENANT_ID);
    }

    @Test
    void activeMembershipIssuesThatTenantsRolesWithoutHeadquartersPermissions() {
        when(tenants.findBySlug("acme")).thenReturn(Optional.of(tenant(TenantStatus.ACTIVE)));
        when(tenants.findById(TENANT_ID)).thenReturn(Optional.of(tenant(TenantStatus.ACTIVE)));
        when(memberships.findByIdUserIdAndIdTenantId(USER_ID, TENANT_ID))
                .thenReturn(Optional.of(membership(true, MembershipStatus.ACTIVE)));
        when(tenantRoles.findAllWithRoleByUserIdAndTenantId(USER_ID, TENANT_ID)).thenReturn(List.of(
                UserTenantRoleEntity.builder()
                        .id(new UserTenantRoleId(USER_ID, TENANT_ID, "payroll_reader"))
                        .role(RoleEntity.builder()
                                .code("payroll_reader")
                                .scope(RoleScope.TENANT)
                                .permissions(new String[] {"payroll:read"})
                                .build())
                        .scope(RoleScope.TENANT)
                        .build()));

        Optional<AccessTokenClaims> claims = loginTokens.tenantClaims(USER_ID, "acme");

        assertThat(claims).isPresent();
        assertThat(claims.get().tenantId()).isEqualTo(TENANT_ID);
        assertThat(claims.get().roles()).containsExactly("payroll_reader", "root");
        assertThat(claims.get().permissions()).containsExactly("payroll:read");
    }

    private static TenantEntity tenant(TenantStatus status) {
        return TenantEntity.builder()
                .id(TENANT_ID)
                .name("Acme")
                .slug("acme")
                .status(status)
                .build();
    }

    private static UserTenantMembershipEntity membership(boolean root, MembershipStatus status) {
        return UserTenantMembershipEntity.builder()
                .id(new UserTenantMembershipId(USER_ID, TENANT_ID))
                .root(root)
                .status(status)
                .build();
    }
}
