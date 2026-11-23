package com.goodlifecoder.groupware.security.jwt;

import com.goodlifecoder.groupware.iam.entity.UserPlatformRoleEntity;
import com.goodlifecoder.groupware.iam.entity.UserTenantRoleEntity;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.UUID;

/**
 * 액세스 토큰에 실을 권한. 본사 토큰은 tenantId 가 없다. 테넌트 토큰에는 본사 권한을 넣지 않는다.
 */
public record AccessTokenClaims(List<String> roles, List<String> permissions, UUID tenantId) {

    public AccessTokenClaims {
        roles = roles == null ? List.of() : List.copyOf(roles);
        permissions = permissions == null ? List.of() : List.copyOf(permissions);
    }

    /** 본사 역할의 코드와 권한을 모은다. 다른 테넌트 권한은 넣지 않는다. */
    public static AccessTokenClaims platform(List<UserPlatformRoleEntity> assignments) {
        List<String> roles = assignments.stream()
                .map(assignment -> assignment.getRole() == null
                        ? assignment.getId().getRole()
                        : assignment.getRole().getCode())
                .filter(code -> code != null && !code.isBlank())
                .distinct()
                .sorted()
                .toList();
        List<String> permissions = assignments.stream()
                .map(UserPlatformRoleEntity::getRole)
                .filter(Objects::nonNull)
                .flatMap(role -> Arrays.stream(role.getPermissions() == null ? new String[0] : role.getPermissions()))
                .filter(permission -> permission != null && !permission.isBlank())
                .distinct()
                .sorted()
                .toList();
        return new AccessTokenClaims(roles, permissions, null);
    }

    /** 그 테넌트 역할의 코드와 권한만 모은다. 본사 권한은 넣지 않는다. */
    public static AccessTokenClaims tenant(UUID tenantId, boolean root, List<UserTenantRoleEntity> assignments) {
        TreeSet<String> roles = assignments.stream()
                .map(assignment -> assignment.getRole() == null
                        ? assignment.getId().getRole()
                        : assignment.getRole().getCode())
                .filter(code -> code != null && !code.isBlank())
                .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
        if (root) {
            roles.add("root");
        }
        List<String> permissions = assignments.stream()
                .map(UserTenantRoleEntity::getRole)
                .filter(Objects::nonNull)
                .flatMap(role -> Arrays.stream(role.getPermissions() == null ? new String[0] : role.getPermissions()))
                .filter(permission -> permission != null && !permission.isBlank())
                .distinct()
                .sorted()
                .toList();
        return new AccessTokenClaims(List.copyOf(roles), permissions, tenantId);
    }
}
