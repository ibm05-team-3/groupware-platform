package com.goodlifecoder.groupware.security.dto;

/**
 * 본사 테스트 계정 본문. 비밀번호는 평문이다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
public record PlatformTestAccountRequestDTO(String email, String password) {
}
