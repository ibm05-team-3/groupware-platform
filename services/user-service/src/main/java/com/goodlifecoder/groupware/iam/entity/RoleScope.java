package com.goodlifecoder.groupware.iam.entity;

/**
 * 역할이 쓰이는 범위. 본사는 PLATFORM, 테넌트 안은 TENANT.
 */
public enum RoleScope {
    PLATFORM,
    TENANT
}
