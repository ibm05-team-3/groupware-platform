package com.goodlifecoder.groupware.security.controller;

import com.goodlifecoder.groupware.security.dto.PlatformMemberResponse;
import com.goodlifecoder.groupware.security.service.PlatformMemberService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 본사 회원 목록. 본사 역할이 있어야 한다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@RestController
@RequiredArgsConstructor
public class PlatformMemberController {

    private final PlatformMemberService platformMemberService;

    /** 활성 회원과 탈퇴 회원. 확인 전 가입은 넣지 않는다. */
    @GetMapping("/platform/members")
    public List<PlatformMemberResponse> list() {
        return platformMemberService.list();
    }
}
