package com.goodlifecoder.groupware.security.jwt;

import com.goodlifecoder.groupware.security.config.AuthProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

/**
 * ES256 액세스 토큰 발급. subject 는 회원 번호 문자열이다.
 * context 는 account, platform, tenant 중 하나다. permissions 에는 서비스:API 를 싣는다.
 * 테넌트 소속 토큰만 tenant_id 를 가진다. 역할 코드는 넣지 않는다.
 *
 * @author 조휘재
 * 작성일: 2026-11-23
 */
@Component
@RequiredArgsConstructor
public class AccessTokenProvider {

    private final AuthProperties authProperties;
    private JwtEncoder jwtEncoder;
    private JwsHeader header;

    /** context 와 권한을 클레임으로 넣어 서명한다. 회사 안 토큰만 tenant_id 를 넣는다. */
    public String issueAccessToken(String sub, AccessTokenClaims accessClaims) {
        Instant now = Instant.now();
        AccessTokenClaims claims = accessClaims == null ? AccessTokenClaims.account() : accessClaims;

        JwtClaimsSet.Builder builder = JwtClaimsSet.builder()
                .subject(sub)
                .issuedAt(now)
                .expiresAt(now.plus(authProperties.accessTokenExpiration()))
                .id(UUID.randomUUID().toString())
                .issuer(authProperties.accessTokenIssuer())
                .claim("context", claims.context().claim())
                .claim("permissions", claims.permissions());
        if (claims.tenantId() != null) {
            builder.claim("tenant_id", claims.tenantId().toString());
        }

        return jwtEncoder.encode(JwtEncoderParameters.from(header, builder.build()))
                .getTokenValue();
    }

    /** 설정 PEM 으로 인코더와 서명 헤더를 준비한다. */
    @PostConstruct
    public void init() throws Exception {
        jwtEncoder = jwtEncoder(jwtPublicKey(), jwtPrivateKey());
        header = jwsHeader();
    }

    /** 공개키 PEM 을 읽는다. */
    private ECPublicKey jwtPublicKey() throws Exception {
        String pem = authProperties.accessTokenPublic();
        String body = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(body));
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(spec);
    }

    /** 개인키 PEM 을 읽는다. */
    private ECPrivateKey jwtPrivateKey() throws Exception {
        String pem = authProperties.accessTokenPrivate();
        String body = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        var spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body));
        return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(spec);
    }

    /** P-256 JWK 로 ES256 인코더를 만든다. */
    JwtEncoder jwtEncoder(ECPublicKey publicKey, ECPrivateKey privateKey) {
        ECKey jwk = new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .keyID(authProperties.accessTokenKeyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .build();

        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwk)));
    }

    /** kid 를 붙인 ES256 헤더. */
    private JwsHeader jwsHeader() {
        return JwsHeader.with(SignatureAlgorithm.ES256)
                .keyId(authProperties.accessTokenKeyId())
                .build();
    }
}