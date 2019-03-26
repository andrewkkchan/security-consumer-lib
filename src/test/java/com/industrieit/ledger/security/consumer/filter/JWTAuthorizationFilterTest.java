package com.industrieit.ledger.security.consumer.filter;


import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.industrieit.ledger.security.consumer.constant.SecurityConstants;
import com.industrieit.ledger.security.consumer.helper.ConsumerAlgorithmProvider;
import com.industrieit.ledger.security.consumer.helper.JWKSetLoader;
import com.industrieit.ledger.security.consumer.helper.JWTDecoder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.industrieit.ledger.security.consumer.model.WellKnownJsonUrl;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;

import static org.mockito.ArgumentMatchers.nullable;

public class JWTAuthorizationFilterTest {
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private WellKnownJsonUrl wellKnownJsonUrl;
    @Mock
    private JWKSetLoader jwkSetLoader;
    @Mock
    private ConsumerAlgorithmProvider consumerAlgorithmProvider;
    @Mock
    private JWTDecoder jwtDecoder;
    @InjectMocks
    private JWTAuthorizationFilter jwtAuthorizationFilter;
    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private HttpServletResponse httpServletResponse;
    @Mock
    private FilterChain filterChain;
    @Mock
    private DecodedJWT decodedJWT;

    @Before
    public void before() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetAuthenticationNoBearer() throws IOException, ServletException {
        Mockito.when(httpServletRequest.getHeader(SecurityConstants.HEADER_STRING)).thenReturn("abcdefg");
        jwtAuthorizationFilter.doFilterInternal(httpServletRequest, httpServletResponse, filterChain);
        Mockito.verify(filterChain).doFilter(nullable(ServletRequest.class), nullable(ServletResponse.class));
    }

    @Test(expected = AuthenticationCredentialsNotFoundException.class)
    public void testGetAuthenticationWithBearerWithoutJWK() throws IOException, ServletException, ParseException, JOSEException {
        Mockito.when(httpServletRequest.getHeader(SecurityConstants.HEADER_STRING)).thenReturn("Bearer abcdefg");
        Mockito.when(jwkSetLoader.load(nullable(WellKnownJsonUrl.class))).thenThrow(new ParseException("Parse", 0));
        Mockito.when(consumerAlgorithmProvider.provide(nullable(JWKSet.class))).thenThrow(new AuthenticationCredentialsNotFoundException("Fail to Get JWKS"));
        jwtAuthorizationFilter.doFilterInternal(httpServletRequest, httpServletResponse, filterChain);
    }

    @Test(expected = AuthenticationCredentialsNotFoundException.class)
    public void testGetAuthenticationWithBearerEmptyJWK() throws IOException, ServletException, ParseException, JOSEException {
        Mockito.when(httpServletRequest.getHeader(SecurityConstants.HEADER_STRING)).thenReturn("Bearer abcdefg");
        Mockito.when(jwkSetLoader.load(nullable(WellKnownJsonUrl.class))).thenReturn(new JWKSet());
        Mockito.when(consumerAlgorithmProvider.provide(nullable(JWKSet.class))).thenThrow(new AuthenticationCredentialsNotFoundException("Fail to Get JWKS"));
        jwtAuthorizationFilter.doFilterInternal(httpServletRequest, httpServletResponse, filterChain);
    }

    @Test(expected = AuthenticationCredentialsNotFoundException.class)
    public void testGetAuthenticationWithBearerWithJWKWithoutPrincipal() throws IOException, ServletException, ParseException, JOSEException {
        Mockito.when(httpServletRequest.getHeader(SecurityConstants.HEADER_STRING)).thenReturn("Bearer abcdefg");
        Mockito.when(jwkSetLoader.load(nullable(WellKnownJsonUrl.class))).thenReturn(new JWKSet());
        Mockito.when(consumerAlgorithmProvider.provide(nullable(JWKSet.class))).thenReturn(Algorithm.none());
        Mockito.when(jwtDecoder.decode(nullable(String.class), nullable(Algorithm.class))).thenReturn(decodedJWT);
        jwtAuthorizationFilter.doFilterInternal(httpServletRequest, httpServletResponse, filterChain);
    }

    @Test
    public void testGetAuthenticationWithBearerWithJWKWithPrincipal() throws IOException, ServletException, ParseException, JOSEException {
        Mockito.when(httpServletRequest.getHeader(SecurityConstants.HEADER_STRING)).thenReturn("Bearer abcdefg");
        Mockito.when(jwkSetLoader.load(nullable(WellKnownJsonUrl.class))).thenReturn(new JWKSet());
        Mockito.when(consumerAlgorithmProvider.provide(nullable(JWKSet.class))).thenReturn(Algorithm.none());
        Mockito.when(jwtDecoder.decode(nullable(String.class), nullable(Algorithm.class))).thenReturn(decodedJWT);
        Mockito.when(decodedJWT.getSubject()).thenReturn("user");
        Mockito.when(decodedJWT.getClaim(SecurityConstants.AUTHORITIES)).thenReturn(new NullClaim());
        jwtAuthorizationFilter.doFilterInternal(httpServletRequest, httpServletResponse, filterChain);
        Mockito.verify(filterChain).doFilter(nullable(ServletRequest.class), nullable(ServletResponse.class));
    }
}
