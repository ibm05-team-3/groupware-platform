package com.goodlifecoder.groupware.user.entity;

import com.goodlifecoder.groupware.common.entity.BaseTimeEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.*;

/**
 * 회원. 로그인 이메일은 이 행에 있다. 소셜만 연결한 회원은 비밀번호가 비어 있다.
 *
 * @author 조휘재
 * 작성일: 2026-10-16
 */
@Builder
@ToString
@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity extends BaseTimeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // 커뮤니티와 헤더에 보여주는 이름. 비어 있을 수 있다.
    @Column(length = 100)
    private String nickname;

    // 로그인 이메일. 소셜 전용 회원과 탈퇴 회원은 비어 있고, 있는 값은 유일하다.
    @Column(length = 255, unique = true)
    private String email;

    @ToString.Exclude
    @Column(length = 255)
    private String password;

    // 활성화 여부 (비활성화 / 회원탈퇴)
    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    /** 탈퇴. 로그인을 막고 닉네임, 이메일, 비밀번호를 지운다. 회원 행은 남긴다. */
    public void withdraw() {
        this.enabled = false;
        this.nickname = null;
        this.email = null;
        this.password = null;
    }

    /** 인코딩된 비밀번호로 바꾼다. */
    public void changePassword(String encodedPassword) {
        this.password = encodedPassword;
    }

    /** 로그인을 다시 허용한다. */
    public void activate() {
        this.enabled = true;
    }

    /** 커뮤니티에 보이는 이름을 바꾼다. null 이면 비운다. */
    public void rename(String nickname) {
        this.nickname = nickname;
    }

    // 계정 잠금 여부
    @Column(nullable = false)
    @Builder.Default
    private boolean accountNonLocked = true;
}
