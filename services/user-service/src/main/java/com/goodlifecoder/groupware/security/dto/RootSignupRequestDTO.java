package com.goodlifecoder.groupware.security.dto;

/** 루트 가입 메일 요청. 비밀번호는 받지 않는다. */
public record RootSignupRequestDTO(String email) {
}
