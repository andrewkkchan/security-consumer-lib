package com.statrys.security.consumer.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.statrys.security.consumer.constant.SecurityConstants;
import com.statrys.security.consumer.helper.JWKSetLoader;
import com.statrys.security.consumer.model.WellKnownJsonUrl;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.stream.Collectors;

import static com.auth0.jwt.algorithms.Algorithm.RSA256;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    private final WellKnownJsonUrl wellKnownJsonUrl;
    private final JWKSetLoader jwkSetLoader;


    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, WellKnownJsonUrl wellKnownJsonUrl, JWKSetLoader jwkSetLoader) {
        super(authenticationManager);
        this.wellKnownJsonUrl = wellKnownJsonUrl;
        this.jwkSetLoader = jwkSetLoader;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = request.getHeader(SecurityConstants.HEADER_STRING);
        if (token == null || !token.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }
        UsernamePasswordAuthenticationToken authentication;
        try {
            authentication = getAuthentication(token);
        } catch (ParseException | JOSEException e) {
            throw new AuthenticationCredentialsNotFoundException("Fail to get Authentication");
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(@NonNull String token) throws IOException, ParseException, JOSEException {
        // parse the token.
        JWKSet jwkSet = jwkSetLoader.load(wellKnownJsonUrl);
        if (jwkSet.getKeys().isEmpty() || !(jwkSet.getKeys().get(0) instanceof RSAKey)) {
            throw new AuthenticationCredentialsNotFoundException("Fail to get JWKS");
        }
        RSAKey rsaKey = (RSAKey) jwkSet.getKeys().get(0);
        RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
        Algorithm algorithm = RSA256(rsaPublicKey, null);
        DecodedJWT decodedJWT = JWT.require(algorithm)
                .build()
                .verify(token.replace(SecurityConstants.TOKEN_PREFIX, ""));
        String principal = decodedJWT.getSubject();
        List<SimpleGrantedAuthority> simpleGrantedAuthorities = null;
        if (decodedJWT.getClaim(SecurityConstants.AUTHORITIES) != null) {
            simpleGrantedAuthorities = decodedJWT.getClaim(SecurityConstants.AUTHORITIES).asList(String.class)
                    .stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        }
        if (principal != null) {
            return new UsernamePasswordAuthenticationToken(principal, null, simpleGrantedAuthorities);
        } else {
            throw new AuthenticationCredentialsNotFoundException("Fail to parse the principal from the token");
        }
    }
}

