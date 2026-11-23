package com.goodlifecoder.groupware.security.dto;

/**
 * 이메일 로그인 본문.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
public record LoginRequestDTO(String email, String password, String tenant) {
}
