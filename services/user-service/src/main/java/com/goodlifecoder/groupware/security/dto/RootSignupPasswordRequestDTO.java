package com.goodlifecoder.groupware.security.dto;

/** 확인된 루트 가입에 비밀번호를 붙인다. */
public record RootSignupPasswordRequestDTO(String signupToken, String password) {
}
