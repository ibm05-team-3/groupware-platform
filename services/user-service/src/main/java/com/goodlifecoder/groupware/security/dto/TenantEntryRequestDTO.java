package com.goodlifecoder.groupware.security.dto;

/**
 * 회사 선택 본문. tenant 는 회사 slug 이다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
public record TenantEntryRequestDTO(String tenant) {
}
