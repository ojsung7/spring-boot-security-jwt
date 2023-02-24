package com.example.demo.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	// 최소 256bit로 하는 것이 좋음
	private static final String SECRET_KEY = "33743677397A24432646294A404E635266556A586E5A7234753778214125442A";

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	// claim 추출하기
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	
	public String generateToken(UserDetails userDetails) {
		return generateToken(new HashMap<>(), userDetails);
	}
	
	// jwt 토큰 생성하기
	public String generateToken(
			Map<String, Object> extracClaims,
			UserDetails userDetails) {
		return Jwts
				.builder()
				.setClaims(extracClaims)
				.setSubject(userDetails.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis())) // 언제 생성되었는지
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // 유효기간 24시간으로 설정
				.signWith(getSignInKey(), SignatureAlgorithm.HS256)
				.compact();
	}
	
	// jwt 검증하기
	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
	}

	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	private Claims extractAllClaims(String toeken) {
		return Jwts
				.parserBuilder()
				.setSigningKey(getSignInKey())
				.build()
				.parseClaimsJws(toeken)
				.getBody();
	}

	private Key getSignInKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
