package org.amnezia.awg.config;

import org.junit.Test;

import java.util.Optional;

public class InetEndPointTest {

    @Test
    public void resolveViaSrv() throws ParseException {
        InetEndpoint inetEndpoint = InetEndpoint.parse("text.example.com:51820");
        Optional<InetEndpoint> resolved = inetEndpoint.getResolved();
        resolved.ifPresent(System.out::println);
    }
}