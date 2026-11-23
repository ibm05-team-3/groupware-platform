package com.goodlifecoder.groupware.security.dto;

/**
 * 이메일 회원가입 본문.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
public record SignupRequestDTO(String email, String password) {
}
