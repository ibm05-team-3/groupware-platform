package com.goodlifecoder.groupware.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.goodlifecoder.groupware.security.config.AuthProperties;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AccessTokenProviderTest {

    @Test
    void accessTokenCarriesRolesAndPermissionsAndOmitsTenantBeforeEntry() throws Exception {
        KeyPair pair = ecKey();
        AccessTokenProvider provider = provider(pair);
        UUID userId = UUID.fromString("00000000-0000-0000-0000-000000000001");

        String token = provider.issueAccessToken(
                userId.toString(),
                new AccessTokenClaims(TokenContext.PLATFORM, List.of("hr:*", "user:read"), null));

        JWTClaimsSet claims = claims(token, pair);
        assertThat(claims.getSubject()).isEqualTo(userId.toString());
        assertThat(claims.getStringClaim("context")).isEqualTo("platform");
        assertThat(claims.getClaim("roles")).isNull();
        assertThat(claims.getStringListClaim("permissions")).containsExactly("hr:*", "user:read");
        assertThat(claims.getClaim("tenant_id")).isNull();
        assertThat(claims.getClaim("scope")).isNull();
    }

    @Test
    void accessTokenCarriesTenantIdOnlyForATenantToken() throws Exception {
        KeyPair pair = ecKey();
        AccessTokenProvider provider = provider(pair);
        UUID tenantId = UUID.fromString("00000000-0000-0000-0000-000000000002");

        String token = provider.issueAccessToken(
                "user",
                new AccessTokenClaims(TokenContext.TENANT, List.of("payroll:read"), tenantId));

        JWTClaimsSet claims = claims(token, pair);
        assertThat(claims.getStringClaim("context")).isEqualTo("tenant");
        assertThat(claims.getStringClaim("tenant_id")).isEqualTo(tenantId.toString());
        assertThat(claims.getClaim("roles")).isNull();
        assertThat(claims.getStringListClaim("permissions")).containsExactly("payroll:read");
    }

    private static JWTClaimsSet claims(String token, KeyPair pair) throws Exception {
        SignedJWT signed = SignedJWT.parse(token);
        assertThat(signed.verify(new ECDSAVerifier((ECPublicKey) pair.getPublic()))).isTrue();
        return signed.getJWTClaimsSet();
    }

    private static AccessTokenProvider provider(KeyPair pair) throws Exception {
        AccessTokenProvider provider = new AccessTokenProvider(new AuthProperties(
                pem("PUBLIC KEY", pair.getPublic().getEncoded()),
                pem("PRIVATE KEY", pair.getPrivate().getEncoded()),
                "test-key",
                "user-service",
                Duration.ofMinutes(10),
                Duration.ofDays(14),
                Duration.ofSeconds(30)));
        provider.init();
        return provider;
    }

    private static KeyPair ecKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static String pem(String type, byte[] encoded) {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }
}
