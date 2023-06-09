package com.mudassir.authenticationservice.providers;

import com.mudassir.authenticationservice.exception.CommonRuntimeException;
import com.mudassir.authenticationservice.models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

  @Value("${app.jwt-secret}")
  private String jwtSecret;

  @Value("${app-jwt-expiration-milliseconds}")
  private long jwtExpirationDate;

  // generate JWT token
  public String generateToken(User user) {
    String username = user.getUsername();

    Date currentDate = new Date();

    Date expireDate = new Date(currentDate.getTime() + jwtExpirationDate);

    String token = Jwts
      .builder()
      .setSubject(username)
      .setIssuedAt(new Date())
      .setExpiration(expireDate)
      .signWith(key())
      .compact();
    return token;
  }

  private Key key() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }

  // get username from Jwt token
  public String getUsername(String token) {
    Claims claims = Jwts
      .parserBuilder()
      .setSigningKey(key())
      .build()
      .parseClaimsJws(token)
      .getBody();
    String username = claims.getSubject();
    return username;
  }

  // validate Jwt token
  public boolean validateToken(String token) {
    try {
      Jwts.parserBuilder().setSigningKey(key()).build().parse(token);
      return true;
    } catch (MalformedJwtException ex) {
      throw new CommonRuntimeException(HttpStatus.BAD_REQUEST, "Invalid JWT token");
    } catch (ExpiredJwtException ex) {
      throw new CommonRuntimeException(HttpStatus.BAD_REQUEST, "Expired JWT token");
    } catch (UnsupportedJwtException ex) {
      throw new CommonRuntimeException(HttpStatus.BAD_REQUEST, "Unsupported JWT token");
    } catch (IllegalArgumentException ex) {
      throw new CommonRuntimeException(
        HttpStatus.BAD_REQUEST,
        "JWT claims string is empty."
      );
    }
  }
}
