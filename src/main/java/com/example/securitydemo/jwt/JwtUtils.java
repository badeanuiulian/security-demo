package com.example.securitydemo.jwt;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

/**
 JwtUtils
 → Contains utility methods
 for generating, parsing, and
 validating JWTs.
 →Include generating a token
 from a username, validating a
 JWT, and extracting the
 username from a token.
 */
@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Remove Bearer prefix
        }
        return null;
    }

    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload().getSubject();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}

/**
 Annotations
 @Component: This annotation indicates that the class is a Spring component. It allows Spring to automatically detect and register the class as a bean in the application context.
 Fields
 Logger logger: A logger instance for logging messages.
 @Value(“${spring.app.jwtSecret}”): Injects the value of the jwtSecret property from the application’s configuration.
 @Value(“${spring.app.jwtExpirationMs}”): Injects the value of the jwtExpirationMs property from the application’s configuration.
 Methods
    getJwtFromHeader(HttpServletRequest request):
 Retrieves the JWT token from the Authorization header of the HTTP request.
 Logs the Authorization header for debugging purposes.
 If the header starts with "Bearer ", it extracts and returns the token; otherwise, it returns null.

    generateTokenFromUsername(UserDetails userDetails):
 Generates a JWT token using the username from the UserDetails object.
 Sets the token’s subject to the username, the issue date to the current date, and the expiration date to the current date plus the configured expiration time.
 Signs the token with the secret key and returns the compact representation of the token.

    getUserNameFromJwtToken(String token):
 Parses the JWT token to extract the username.
 Uses the secret key to verify the token’s signature and returns the subject (username).

    key():
 Decodes the jwtSecret from Base64 and returns a Key object for signing and verifying JWT tokens.
    validateJwtToken(String authToken):
 Validates the JWT token by parsing and verifying its signature.
 Logs any exceptions that occur during validation, such as malformed, expired, unsupported, or empty tokens.
 Returns true if the token is valid; otherwise, returns false.
 */
