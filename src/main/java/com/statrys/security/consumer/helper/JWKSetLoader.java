package com.statrys.security.consumer.helper;

import com.nimbusds.jose.jwk.JWKSet;
import com.statrys.security.consumer.model.WellKnownJsonUrl;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;

@Component
public class JWKSetLoader {
    public JWKSet load(WellKnownJsonUrl wellKnownJsonUrl) throws IOException, ParseException {
        return JWKSet.load(new URL(wellKnownJsonUrl.getUrl()));
    }
}
