package com.goodlifecoder.groupware.security.dto;

/**
 * 가입 확인 본문. email 은 토큰을 받은 주소이고 code 는 메일의 32바이트 난수다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
public record SignupEmailVerificationRequestDTO(String email, String code) {
}
