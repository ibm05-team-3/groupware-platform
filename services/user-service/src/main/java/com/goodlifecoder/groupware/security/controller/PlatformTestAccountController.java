package com.goodlifecoder.groupware.security.controller;

import com.goodlifecoder.groupware.security.dto.PlatformTestAccountRequestDTO;
import com.goodlifecoder.groupware.security.service.PlatformTestAccountService;
import com.goodlifecoder.groupware.security.service.SignupService.EmailAlreadyUsedException;
import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupException;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 본사 테스트 계정. 본사 역할이 있어야 한다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@RestController
@RequiredArgsConstructor
public class PlatformTestAccountController {

    private final PlatformTestAccountService platformTestAccountService;

    /** 확인 메일 없이 활성 계정을 만든다. 형식 오류는 400, 이미 쓴 이메일은 409. */
    @PostMapping("/platform/test-accounts")
    public ResponseEntity<Map<String, String>> create(@RequestBody PlatformTestAccountRequestDTO request) {
        try {
            platformTestAccountService.create(request.email(), request.password());
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (InvalidSignupException ex) {
            return ResponseEntity.badRequest().body(Map.of("code", "INVALID_REQUEST"));
        } catch (EmailAlreadyUsedException ex) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("code", "EMAIL_TAKEN"));
        }
    }
}
