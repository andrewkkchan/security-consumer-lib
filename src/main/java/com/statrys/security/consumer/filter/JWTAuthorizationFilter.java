package com.statrys.security.consumer.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.statrys.security.consumer.constant.SecurityConstants;
import com.statrys.security.consumer.model.WellKnownJsonUrl;
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
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.stream.Collectors;

import static com.auth0.jwt.algorithms.Algorithm.RSA256;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    private final WellKnownJsonUrl wellKnownJsonUrl;


    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, WellKnownJsonUrl wellKnownJsonUrl) {
        super(authenticationManager);
        this.wellKnownJsonUrl = wellKnownJsonUrl;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader(SecurityConstants.HEADER_STRING);

        if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = null;
        try {
            authentication = getAuthentication(request);
        } catch (ParseException | JOSEException e) {
            e.printStackTrace();
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) throws IOException, ParseException, JOSEException {
        String token = request.getHeader(SecurityConstants.HEADER_STRING);
        if (token != null) {
            // parse the token.
            JWKSet jwkSet = JWKSet.load(new URL(wellKnownJsonUrl.getUrl()));
            if (jwkSet.getKeys().isEmpty() || !(jwkSet.getKeys().get(0) instanceof RSAKey)){
                return null;
            }
            com.nimbusds.jose.jwk.RSAKey rsaKey = (com.nimbusds.jose.jwk.RSAKey) jwkSet.getKeys().get(0);
            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
            Algorithm algorithm = RSA256(rsaPublicKey, null);
            DecodedJWT decodedJWT = JWT.require(algorithm)
                    .build()
                    .verify(token.replace(SecurityConstants.TOKEN_PREFIX, ""));
            String principal = decodedJWT.getSubject();

            if (principal != null) {
                return new UsernamePasswordAuthenticationToken(principal, null, decodedJWT.getClaim(SecurityConstants.AUTHORITIES).asList(String.class)
                        .stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
            }
            return null;
        }
        return null;
    }
}

