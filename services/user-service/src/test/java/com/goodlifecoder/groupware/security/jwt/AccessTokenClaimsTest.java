package com.goodlifecoder.groupware.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.goodlifecoder.groupware.iam.entity.RoleEntity;
import com.goodlifecoder.groupware.iam.entity.RoleScope;
import com.goodlifecoder.groupware.iam.entity.UserPlatformRoleEntity;
import com.goodlifecoder.groupware.iam.entity.UserPlatformRoleId;
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
}
