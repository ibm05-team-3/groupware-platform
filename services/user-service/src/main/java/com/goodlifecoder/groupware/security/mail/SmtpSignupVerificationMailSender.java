package com.goodlifecoder.groupware.security.mail;

import com.goodlifecoder.groupware.common.config.MailProperties;
import com.goodlifecoder.groupware.security.dao.PendingSignupStore;
import com.goodlifecoder.groupware.security.dao.SignupEmailCodeStore;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;

/**
 * Gmail SMTP. 접속 정보는 spring.mail.* 이고 비밀번호는 MAIL_APP_PASSWORD 이다.
 *
 * @author 조휘재
 * 작성일: 2026-11-11
 */
@Component
@ConditionalOnProperty(prefix = "app.mail", name = "enabled", havingValue = "true")
public class SmtpSignupVerificationMailSender implements SignupVerificationMailSender {

    private final JavaMailSender mailSender;
    private final MailProperties mailProperties;

    /** 보내는 주소가 없으면 기동을 멈춘다. */
    public SmtpSignupVerificationMailSender(JavaMailSender mailSender, MailProperties mailProperties) {
        if (mailProperties.from() == null || mailProperties.from().isBlank()) {
            throw new IllegalStateException("app.mail.enabled=true이면 MAIL_USERNAME(보내는 Gmail 주소)이 필요합니다");
        }
        this.mailSender = mailSender;
        this.mailProperties = mailProperties;
    }

    /** HTML 가입 확인 메일을 보낸다. 코드는 로그에 남기지 않는다. */
    @Override
    public void send(String to, String code) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, StandardCharsets.UTF_8.name());
            helper.setFrom(mailProperties.from(), mailProperties.fromName());
            helper.setTo(to);
            helper.setSubject("Groupware 회원가입 확인");
            helper.setText(html(code), true);
            mailSender.send(message);
        } catch (MessagingException | UnsupportedEncodingException ex) {
            throw new IllegalStateException("회원가입 확인 메일을 보내지 못했습니다.", ex);
        }
    }

    /** 확인 토큰과 10분 만료, 대기 보관 기간을 담은 HTML. 토큰은 이스케이프한다. */
    private String html(String code) {
        String escapedCode = HtmlUtils.htmlEscape(code);
        long minutes = SignupEmailCodeStore.TTL.toMinutes();
        long days = PendingSignupStore.RETENTION.toDays();
        return """
                <!doctype html>
                <html lang="ko"><body style="margin:0;padding:24px;background:#f4f4f2;font-family:'Apple SD Gothic Neo','Malgun Gothic',sans-serif;color:#222">
                <div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:8px;padding:32px">
                <h1 style="margin:0 0 16px;font-size:20px">회원가입 확인</h1>
                <p style="font-size:15px;line-height:1.6">Groupware 가입을 확인하려면 아래 코드를 입력해 주세요. 이 코드는 %d분 동안만 사용할 수 있습니다. 확인하지 않으면 가입 정보는 %d일 뒤에 삭제되고, 그 이메일로 다시 가입할 수 있습니다. 가입하지 않았다면 이 메일을 무시하세요.</p>
                <p style="margin:28px 0 0;font-size:16px;word-break:break-all;font-weight:bold">%s</p>
                <p style="margin:32px 0 0;font-size:12px;color:#888">본 메일은 발신 전용입니다.</p>
                </div></body></html>
                """.formatted(minutes, days, escapedCode);
    }
}
