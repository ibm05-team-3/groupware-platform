package com.goodlifecoder.groupware.iam.repository;

import com.goodlifecoder.groupware.iam.entity.UserPlatformRoleEntity;
import com.goodlifecoder.groupware.iam.entity.UserPlatformRoleId;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * 본사 역할. 테넌트 없이 회원에게 붙은 PLATFORM 역할이다.
 */
public interface UserPlatformRoleRepository extends JpaRepository<UserPlatformRoleEntity, UserPlatformRoleId> {

    /** 이 회원에게 본사 역할이 하나라도 있으면 true. */
    boolean existsByIdUserId(UUID userId);

    /** 본사 역할과 그 권한을 함께 읽는다. */
    @Query("""
            select assignment
            from UserPlatformRoleEntity assignment
            join fetch assignment.role
            where assignment.id.userId = :userId
            """)
    List<UserPlatformRoleEntity> findAllWithRoleByUserId(@Param("userId") UUID userId);
}
