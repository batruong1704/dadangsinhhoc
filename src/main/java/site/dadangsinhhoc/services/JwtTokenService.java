package site.dadangsinhhoc.services;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import site.dadangsinhhoc.exception.TokenGenerationException;
import site.dadangsinhhoc.models.UserModel;
import site.dadangsinhhoc.repositories.UserRepository;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.StringJoiner;

@Service
@Slf4j
public class JwtTokenService implements TokenService {

    private final UserRepository userRepository;
    @Value("${jwt.signerKey}")
    private String signerKey;

    @Autowired
    public JwtTokenService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserModel validateAndGetUserFromToken(String token) throws JOSEException, ParseException {
        JWSVerifier verifier = new MACVerifier(signerKey.getBytes());
        SignedJWT signedJWT = SignedJWT.parse(token);

        if (signedJWT.verify(verifier)) {
            String username = signedJWT.getJWTClaimsSet().getSubject();
            return userRepository.findByUserName(username);
        }
        return null;
    }

    @Override
    public String generateToken(UserModel userModel) {
        log.info("Starting token generation for user: {}", userModel.getUserName());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);
        log.debug("JWT header created");

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(userModel.getUserName())
                .issuer("dadangsinhhoc.site")
                .issueTime(new Date())
                .expirationTime(new Date(
                        Instant.now().plus(1, ChronoUnit.HOURS).toEpochMilli()
                ))
                .claim("scope", buildScope(userModel))
                .build();
        log.debug("JWT claims set built");

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            jwsObject.sign(new MACSigner(signerKey.getBytes()));
            log.info("Token signed successfully");
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("Error occurred while signing the token", e);
            throw new TokenGenerationException("Failed to generate or sign the token", e);
        }
    }

    private String buildScope(UserModel user) {
        StringJoiner stringJoiner = new StringJoiner(" ");
        if (user.getRole() != null && !user.getRole().isBlank())
            stringJoiner.add(user.getRole());
        return stringJoiner.toString();
    }
}