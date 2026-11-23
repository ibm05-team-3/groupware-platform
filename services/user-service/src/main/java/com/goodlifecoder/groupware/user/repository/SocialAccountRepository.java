package com.goodlifecoder.groupware.user.repository;

import com.goodlifecoder.groupware.user.entity.UserSocialAccountEntity;
import com.goodlifecoder.groupware.user.entity.UserSocialAccountId;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * 소셜 로그인 연결.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@Repository
public interface SocialAccountRepository extends JpaRepository<UserSocialAccountEntity, UserSocialAccountId> {

    /** 그 회원의 소셜 연결을 모두 지운다. */
    @Modifying(flushAutomatically = true)
    @Query("delete from UserSocialAccountEntity account where account.user.id = :userId")
    void deleteByUserId(@Param("userId") UUID userId);

    /** 회원 번호와 소셜 제공자. 관리자 목록에서 제공자 이름을 붙인다. */
    @Query("select account.user.id, account.id.providerType from UserSocialAccountEntity account")
    List<Object[]> findUserIdsAndProviders();
}
