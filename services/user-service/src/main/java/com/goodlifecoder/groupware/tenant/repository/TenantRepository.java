package com.goodlifecoder.groupware.tenant.repository;

import com.goodlifecoder.groupware.tenant.entity.TenantEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * 테넌트. slug 는 로그인 본문이 회사를 가리키는 값이다.
 */
public interface TenantRepository extends JpaRepository<TenantEntity, UUID> {

    /** slug 가 같은 테넌트. 없으면 비운다. */
    Optional<TenantEntity> findBySlug(String slug);
}
