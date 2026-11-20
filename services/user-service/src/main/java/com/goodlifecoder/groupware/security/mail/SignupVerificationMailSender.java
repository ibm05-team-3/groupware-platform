package com.goodlifecoder.groupware.security.mail;

/**
 * 회원가입 확인 메일. 코드는 가입한 주소로만 가고 로그에는 남기지 않는다.
 *
 * @author 조휘재
 * 작성일: 2026-11-11
 */
public interface SignupVerificationMailSender {
    /** to 로만 가입 확인 토큰을 보낸다. */
    void send(String to, String code);
}
