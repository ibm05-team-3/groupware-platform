package com.goodlifecoder.groupware.iam.repository;

import com.goodlifecoder.groupware.iam.entity.UserPlatformRoleEntity;
import com.goodlifecoder.groupware.iam.entity.UserPlatformRoleId;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * 본사 역할. 테넌트 없이 회원에게 붙은 PLATFORM 역할이다.
 */
public interface UserPlatformRoleRepository extends JpaRepository<UserPlatformRoleEntity, UserPlatformRoleId> {

    /** 이 회원에게 본사 역할이 하나라도 있으면 true. */
    boolean existsByIdUserId(UUID userId);
}
