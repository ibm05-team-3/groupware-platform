package com.goodlifecoder.groupware.security.controller;

import com.goodlifecoder.groupware.security.dto.RootSignupPasswordRequestDTO;
import com.goodlifecoder.groupware.security.dto.RootSignupRequestDTO;
import com.goodlifecoder.groupware.security.dto.SignupEmailVerificationRequestDTO;
import com.goodlifecoder.groupware.security.dto.SignupResendRequestDTO;
import com.goodlifecoder.groupware.security.service.RootSignupService;
import com.goodlifecoder.groupware.security.service.SignupService.EmailAlreadyUsedException;
import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupException;
import com.goodlifecoder.groupware.security.service.SignupService.InvalidSignupTokenException;
import com.goodlifecoder.groupware.security.service.SignupService.MailDisabledException;
import com.goodlifecoder.groupware.security.service.SignupService.MailSendException;
import com.goodlifecoder.groupware.security.service.SignupService.TooManyAttemptsException;
import com.goodlifecoder.groupware.security.service.SignupService.TooManyRequestsException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 루트 가입. 확인 메일은 이메일만 받고, 비밀번호는 확인 뒤에 받는다.
 * 테넌트는 이 API에서 만들지 않는다.
 */
@RestController
@RequiredArgsConstructor
public class RootSignupController {

    private final RootSignupService rootSignupService;

    /** 확인 메일을 보낸다. 성공은 201. */
    @PostMapping("/user/root-signup")
    public ResponseEntity<Map<String, String>> request(
            @RequestBody RootSignupRequestDTO request, HttpServletRequest httpRequest) {
        try {
            rootSignupService.request(request.email(), SignupController.clientIp(httpRequest));
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (InvalidSignupException ex) {
            return ResponseEntity.badRequest().body(Map.of("code", "INVALID_REQUEST"));
        } catch (EmailAlreadyUsedException ex) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("code", "EMAIL_TAKEN"));
        } catch (MailDisabledException ex) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("code", "MAIL_DISABLED"));
        } catch (MailSendException ex) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("code", "MAIL_SEND_FAILED"));
        } catch (TooManyRequestsException ex) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of("code", "TOO_MANY_REQUESTS"));
        }
    }

    /** 확인 토큰을 다시 보낸다. 보낼 대상이 없어도 204. */
    @PostMapping("/user/root-signup/email-verification/resend")
    public ResponseEntity<Map<String, String>> resend(
            @RequestBody SignupResendRequestDTO request, HttpServletRequest httpRequest) {
        try {
            rootSignupService.resend(request.email(), SignupController.clientIp(httpRequest));
            return ResponseEntity.noContent().build();
        } catch (InvalidSignupException ex) {
            return ResponseEntity.badRequest().body(Map.of("code", "INVALID_REQUEST"));
        } catch (MailDisabledException ex) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("code", "MAIL_DISABLED"));
        } catch (MailSendException ex) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("code", "MAIL_SEND_FAILED"));
        } catch (TooManyRequestsException ex) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of("code", "TOO_MANY_REQUESTS"));
        }
    }

    /** 이메일과 토큰을 확인하고 짧은 가입 토큰을 준다. 로그인 세션은 만들지 않는다. */
    @PostMapping("/user/root-signup/email-verification")
    public ResponseEntity<Map<String, String>> confirmEmail(@RequestBody SignupEmailVerificationRequestDTO request) {
        try {
            String signupToken = rootSignupService.confirmEmail(request.email(), request.code());
            return ResponseEntity.ok(Map.of("signupToken", signupToken));
        } catch (TooManyAttemptsException ex) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of("code", "TOO_MANY_ATTEMPTS"));
        } catch (InvalidSignupTokenException ex) {
            return ResponseEntity.badRequest().body(Map.of("code", "INVALID_TOKEN"));
        }
    }

    /** 확인된 이메일에 비밀번호를 붙여 회원을 만든다. 성공은 201. */
    @PostMapping("/user/root-signup/password")
    public ResponseEntity<Map<String, String>> password(@RequestBody RootSignupPasswordRequestDTO request) {
        try {
            rootSignupService.completeWithPassword(request.signupToken(), request.password());
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (InvalidSignupException ex) {
            return ResponseEntity.badRequest().body(Map.of("code", "INVALID_REQUEST"));
        } catch (InvalidSignupTokenException ex) {
            return ResponseEntity.badRequest().body(Map.of("code", "INVALID_TOKEN"));
        } catch (EmailAlreadyUsedException ex) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("code", "EMAIL_TAKEN"));
        }
    }
}
