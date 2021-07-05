package com.binarystudio.academy.springsecurity.security.jwt;

import com.binarystudio.academy.springsecurity.domain.user.model.User;
import com.binarystudio.academy.springsecurity.security.jwt.repository.PasswordChangeRepository;
import com.binarystudio.academy.springsecurity.security.jwt.repository.RefreshTokenRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

@Component
public class JwtProvider {
	private final JwtProperties jwtProperties;
	private Key secretKey;
	private JwtParser jwtParser;

	@Autowired
	RefreshTokenRepository refreshTokenRepository;
	@Autowired
	PasswordChangeRepository passwordChangeRepository;

	@Autowired
	public JwtProvider(JwtProperties jwtProperties) {
		this.jwtProperties = jwtProperties;
	}

	private Key key() {
		if (secretKey == null) {
			byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecret());
			secretKey = Keys.hmacShaKeyFor(keyBytes);
		}
		return secretKey;
	}

	private JwtParser jwtParser() {
		if (jwtParser == null) {
			jwtParser = Jwts.parserBuilder().setSigningKey(key()).build();
		}
		return jwtParser;
	}

	public String generateRefreshToken(User user) {
		Date date = Date.from(LocalDateTime.now()
				.plusSeconds(jwtProperties.getSecs_to_expire_refresh()).toInstant(ZoneOffset.UTC));
		UUID tokenId = UUID.randomUUID();
		String userName = user.getUsername();
		refreshTokenRepository.add(tokenId, userName);
		return Jwts.builder()
				.setSubject(userName)
				.setId(tokenId.toString())
				.setExpiration(date)
				.signWith(key())
				.compact();
	}

	//return userName if token is valid, else return empty optional
	public Optional<String> validateAndDeleteRefreshToken(String refreshToken){
		Claims claims = parseToken(refreshToken);
		UUID tokenId = UUID.fromString(claims.getId());
		String userName = claims.getSubject();
		if (refreshTokenRepository.contains(tokenId, userName)) {
			refreshTokenRepository.delete(tokenId);
			return Optional.of(userName);
		} else
			return Optional.empty();
	}

	public String generatePasswordChangeToken(User user) {
		Date date = Date.from(LocalDateTime.now()
				.plusSeconds(jwtProperties.getSecs_to_expire_change_password()).toInstant(ZoneOffset.UTC));
		UUID tokenId = UUID.randomUUID();
		String userName = user.getUsername();
		passwordChangeRepository.add(tokenId, userName);
		return Jwts.builder()
				.setSubject(userName)
				.setId(tokenId.toString())
				.setExpiration(date)
				.signWith(key())
				.compact();
	}

	//return userName if token is valid, else return empty optional
	public Optional<String> validateAndDeletePasswordChangeToken(String refreshToken){
		Claims claims = parseToken(refreshToken);
		UUID tokenId = UUID.fromString(claims.getId());
		String userName = claims.getSubject();
		if (passwordChangeRepository.contains(tokenId, userName)) {
			passwordChangeRepository.delete(tokenId);
			return Optional.of(userName);
		} else
			return Optional.empty();
	}

	public String generateAccessToken(User user) {
		Date date = Date.from(LocalDateTime.now().plusSeconds(jwtProperties.getSecs_to_expire_access()).toInstant(ZoneOffset.UTC));
		return Jwts.builder()
				.setSubject(user.getUsername())
				.setExpiration(date)
				.signWith(key())
				.compact();
	}

	public String getLoginFromToken(String token) {
		Claims claims = parseToken(token);
		return claims.getSubject();
	}

	private Claims parseToken(String token) {
		try {
			return jwtParser().parseClaimsJws(token).getBody();
		} catch (ExpiredJwtException expEx) {
			throw new JwtException("Token expired", "jwt-expired");
		} catch (UnsupportedJwtException unsEx) {
			throw new JwtException("Unsupported jwt", "jwt-unsupported");
		} catch (MalformedJwtException mjEx) {
			throw new JwtException("Malformed jwt", "jwt-malformed");
		} catch (SignatureException sEx) {
			throw new JwtException("Invalid signature", "jwt-signature");
		} catch (Exception e) {
			throw new JwtException("Invalid token", "jwt-invalid");
		}
	}

}
