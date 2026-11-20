package com.goodlifecoder.groupware.user.repository;

import com.goodlifecoder.groupware.user.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

/**
 * 회원.
 *
 * @author 조휘재
 * 작성일: 2026-10-16
 */
@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {

    /** id가 큰 회원부터 모두 읽는다. */
    List<UserEntity> findAllByOrderByIdDesc();

    /** 이메일로 회원을 찾는다. 이메일은 저장 전에 소문자로 맞춘다. */
    Optional<UserEntity> findByEmail(String email);

    /** 확인 전 가입. 탈퇴 회원은 이메일이 없으므로 여기 나오지 않는다. */
    @Query("""
            select user from UserEntity user
            where user.enabled = false
              and user.email is not null
              and (user.createdAt is null or user.createdAt < :cutoff)
            """)
    List<UserEntity> findUnverifiedCreatedBefore(@Param("cutoff") OffsetDateTime cutoff);
}
