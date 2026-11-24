package com.goodlifecoder.groupware.security.jwt;

import com.goodlifecoder.groupware.iam.entity.UserPlatformRoleEntity;
import com.goodlifecoder.groupware.iam.entity.UserTenantRoleEntity;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * 액세스 토큰에 실을 권한. 역할 코드는 넣지 않는다.
 * 본사 토큰은 tenantId 가 없다. 테넌트 토큰에는 본사 권한을 넣지 않는다.
 */
public record AccessTokenClaims(TokenContext context, List<String> permissions, UUID tenantId) {

    public AccessTokenClaims {
        context = context == null ? TokenContext.ACCOUNT : context;
        permissions = permissions == null ? List.of() : List.copyOf(permissions);
    }

    /** 로그인한 회사 밖. 권한은 없고 tenantId 도 없다. */
    public static AccessTokenClaims account() {
        return new AccessTokenClaims(TokenContext.ACCOUNT, List.of(), null);
    }

    /** 본사 역할이 있으면 platform, 없으면 account. 권한만 모으고 다른 테넌트 권한은 넣지 않는다. */
    public static AccessTokenClaims platform(List<UserPlatformRoleEntity> assignments) {
        boolean assigned = assignments.stream().anyMatch(assignment -> roleCode(assignment) != null);
        List<String> permissions = assignments.stream()
                .map(UserPlatformRoleEntity::getRole)
                .filter(Objects::nonNull)
                .flatMap(role -> Arrays.stream(role.getPermissions() == null ? new String[0] : role.getPermissions()))
                .filter(permission -> permission != null && !permission.isBlank())
                .distinct()
                .sorted()
                .toList();
        return new AccessTokenClaims(assigned ? TokenContext.PLATFORM : TokenContext.ACCOUNT, permissions, null);
    }

    /** 그 테넌트 권한만 모은다. 본사 권한은 넣지 않는다. */
    public static AccessTokenClaims tenant(UUID tenantId, List<UserTenantRoleEntity> assignments) {
        List<String> permissions = assignments.stream()
                .map(UserTenantRoleEntity::getRole)
                .filter(Objects::nonNull)
                .flatMap(role -> Arrays.stream(role.getPermissions() == null ? new String[0] : role.getPermissions()))
                .filter(permission -> permission != null && !permission.isBlank())
                .distinct()
                .sorted()
                .toList();
        return new AccessTokenClaims(TokenContext.TENANT, permissions, tenantId);
    }

    /** 역할 행이 없으면 null. */
    private static String roleCode(UserPlatformRoleEntity assignment) {
        String code = assignment.getRole() == null
                ? assignment.getId().getRole()
                : assignment.getRole().getCode();
        return code == null || code.isBlank() ? null : code;
    }
}
