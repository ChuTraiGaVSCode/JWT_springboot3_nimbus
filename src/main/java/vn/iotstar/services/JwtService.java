package vn.iotstar.services;

import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import vn.iotstar.exceptions.InvalidTokenException;
import vn.iotstar.exceptions.TokenExpiredException;

@Service
public class JwtService {

	@Value("${security.jwt.secret-key}")
	private String secretKey;

	@Value("${security.jwt.expiration-time}")
	private long jwtExpiration;

	public String extractUsername(String token) {
		return extractClaim(token, JWTClaimsSet::getSubject);
	}

	public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
		return claimsResolver.apply(extractAllClaims(token));
	}

	public String generateToken(UserDetails userDetails) {
		return generateToken(new HashMap<>(), userDetails);
	}

	public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
		return buildToken(extraClaims, userDetails, jwtExpiration);
	}

	public long getExpirationTime() {
		return jwtExpiration;
	}

	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return username.equals(userDetails.getUsername());
	}

	private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
		long now = System.currentTimeMillis();

		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
				.subject(userDetails.getUsername())
				.jwtID(UUID.randomUUID().toString())
				.issueTime(new Date(now))
				.expirationTime(new Date(now + expiration));
		extraClaims.forEach(builder::claim);

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build();
		SignedJWT signedJWT = new SignedJWT(header, builder.build());

		try {
			signedJWT.sign(new MACSigner(getSignInKey()));
		} catch (JOSEException e) {
			throw new IllegalStateException("Cannot sign JWT", e);
		}
		return signedJWT.serialize();
	}

	private JWTClaimsSet extractAllClaims(String token) {
		try {
			SignedJWT signedJWT = SignedJWT.parse(token);

			if (!JWSAlgorithm.HS256.equals(signedJWT.getHeader().getAlgorithm())) {
				throw new InvalidTokenException("Unsupported JWT algorithm");
			}
			if (!signedJWT.verify(new MACVerifier(getSignInKey()))) {
				throw new InvalidTokenException("JWT signature does not match locally computed signature");
			}

			JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
			Date expiration = claims.getExpirationTime();
			if (expiration == null || expiration.before(new Date())) {
				throw new TokenExpiredException("JWT expired at " + expiration);
			}
			return claims;
		} catch (ParseException e) {
			throw new InvalidTokenException("Invalid compact JWT string: " + e.getMessage(), e);
		} catch (JOSEException e) {
			throw new InvalidTokenException("Cannot verify JWT: " + e.getMessage(), e);
		}
	}

	private byte[] getSignInKey() {
		return Base64.getDecoder().decode(secretKey);
	}
}
