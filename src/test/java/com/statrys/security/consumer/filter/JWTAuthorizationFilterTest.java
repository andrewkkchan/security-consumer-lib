package com.statrys.security.consumer.filter;


import com.statrys.security.consumer.constant.SecurityConstants;
import com.statrys.security.consumer.helper.JWKSetLoader;
import com.statrys.security.consumer.model.WellKnownJsonUrl;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.nullable;

public class JWTAuthorizationFilterTest {
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private WellKnownJsonUrl wellKnownJsonUrl;
    @Mock
    private JWKSetLoader jwkSetLoader;
    @InjectMocks
    private JWTAuthorizationFilter jwtAuthorizationFilter;
    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private HttpServletResponse httpServletResponse;
    @Mock
    private FilterChain filterChain;
    @Before
    public void before() {
        MockitoAnnotations.initMocks(this);
    }
    @Test
    public void testGetAuthentication() throws IOException, ServletException {
        Mockito.when(httpServletRequest.getHeader(SecurityConstants.HEADER_STRING)).thenReturn("abcdefg");
        jwtAuthorizationFilter.doFilterInternal(httpServletRequest, httpServletResponse, filterChain);
        Mockito.verify(filterChain).doFilter(nullable(ServletRequest.class), nullable(ServletResponse.class));
    }

}
