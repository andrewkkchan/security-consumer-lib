package com.statrys.security.consumer.service;

import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.UUID;

public interface ConsumerTokenService {
    DecodedJWT decode(String encryptedToken);

    UUID getUserSlug();
}
