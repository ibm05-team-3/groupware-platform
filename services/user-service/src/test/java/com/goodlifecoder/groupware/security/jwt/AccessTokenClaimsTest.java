package com.goodlifecoder.groupware.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.goodlifecoder.groupware.iam.entity.RoleEntity;
import com.goodlifecoder.groupware.iam.entity.RoleScope;
import com.goodlifecoder.groupware.iam.entity.UserPlatformRoleEntity;
import com.goodlifecoder.groupware.iam.entity.UserPlatformRoleId;
import com.goodlifecoder.groupware.iam.entity.UserTenantRoleEntity;
import com.goodlifecoder.groupware.iam.entity.UserTenantRoleId;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AccessTokenClaimsTest {

    @Test
    void platformClaimsCollectRoleCodesAndPermissionsWithoutTenant() {
        UUID userId = UUID.fromString("00000000-0000-0000-0000-000000000001");
        AccessTokenClaims claims = AccessTokenClaims.platform(List.of(
                assignment(userId, "ops", "user:read", "hr:*"),
                assignment(userId, "audit", "hr:*", "payroll:read")));

        assertThat(claims.roles()).containsExactly("audit", "ops");
        assertThat(claims.permissions()).containsExactly("hr:*", "payroll:read", "user:read");
        assertThat(claims.tenantId()).isNull();
    }

    @Test
    void tenantClaimsKeepThatTenantOnlyAndMarkRoot() {
        UUID userId = UUID.fromString("00000000-0000-0000-0000-000000000002");
        UUID tenantId = UUID.fromString("00000000-0000-0000-0000-000000000010");
        AccessTokenClaims claims = AccessTokenClaims.tenant(tenantId, true, List.of(
                tenantAssignment(userId, tenantId, "payroll_reader", "payroll:read")));

        assertThat(claims.roles()).containsExactly("payroll_reader", "root");
        assertThat(claims.permissions()).containsExactly("payroll:read");
        assertThat(claims.tenantId()).isEqualTo(tenantId);
    }

    @Test
    void platformClaimsAreEmptyWhenTheUserHasNoHeadquartersRole() {
        AccessTokenClaims claims = AccessTokenClaims.platform(List.of());

        assertThat(claims.roles()).isEmpty();
        assertThat(claims.permissions()).isEmpty();
        assertThat(claims.tenantId()).isNull();
    }

    private static UserPlatformRoleEntity assignment(UUID userId, String code, String... permissions) {
        return UserPlatformRoleEntity.builder()
                .id(new UserPlatformRoleId(userId, code))
                .role(RoleEntity.builder()
                        .code(code)
                        .scope(RoleScope.PLATFORM)
                        .permissions(permissions)
                        .build())
                .scope(RoleScope.PLATFORM)
                .build();
    }

    private static UserTenantRoleEntity tenantAssignment(UUID userId, UUID tenantId, String code, String... permissions) {
        return UserTenantRoleEntity.builder()
                .id(new UserTenantRoleId(userId, tenantId, code))
                .role(RoleEntity.builder()
                        .code(code)
                        .scope(RoleScope.TENANT)
                        .permissions(permissions)
                        .build())
                .scope(RoleScope.TENANT)
                .build();
    }
}
