package com.congobs.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    /** Extract Subject (Email)  the JWT-Token
     */
    public String extractUsernameFromJWTToken(String jwtToken) {
        return extractOneClaim(jwtToken, Claims::getSubject);
    }

    /** Generate  the JWT-Token
     */
    public String generateJWTToken(String email) {
        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
            .claims()
            .add(claims)
            .subject(email)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
            .and()
            .signWith(getSigningKey())
            .compact();
    }

    /** Extract a SPECIFIC claim from the
     *  JWT-Token
     */
    public <T> T extractOneClaim(String jwtToken, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jwtToken);
        return claimsResolver.apply(claims);
    }

    public boolean isJWTTokenValid(String jwtToken, UserDetails userDetails) {
        String usernameFromJWTToken = extractUsernameFromJWTToken(jwtToken);
        return (usernameFromJWTToken.equals(userDetails.getUsername())) &&
            !isJWTTokenNotExpired(jwtToken);
    }


    /** Generate the JWT-Token signingKey from a generated secretKey- for signing the
     *  JWT-Token
     */
    private Key getSigningKey() {
        String secretKey = "";
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            SecretKey sk = keyGen.generateKey();
            secretKey =  Base64.getEncoder().encodeToString(sk.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /** Extract ALL claims from the
     *  JWT-Token
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getPayload();
    }

    /** Extract JWT-Token-Expiration-Date the JWT-Token
     */
    private Date extractExpirationFromJWTToken(String jwtToken) {
        return extractOneClaim(jwtToken, Claims::getExpiration);
    }

    private boolean isJWTTokenNotExpired (String jwtToken) {
        return extractExpirationFromJWTToken(jwtToken).before(new Date());
    }
}

