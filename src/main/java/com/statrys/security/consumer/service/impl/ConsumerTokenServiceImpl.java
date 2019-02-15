package com.statrys.security.consumer.service.impl;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.statrys.security.consumer.service.ConsumerTokenService;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class ConsumerTokenServiceImpl implements ConsumerTokenService {
    @Override
    public DecodedJWT decode(String encryptedToken) {
        return null;
    }

    @Override
    public UUID getUserSlug() {
        return null;
    }
}
