package org.amnezia.awg.config;

import org.junit.Test;

import java.util.Optional;

public class InetEndPointTest {

    @Test
    public void parse() throws ParseException {
        parse("_wireguard._udp.example.top:51820");
    }

    public void parse(String endpoint) throws ParseException {
        InetEndpoint inetEndpoint = InetEndpoint.parse(endpoint);
        Optional<InetEndpoint> resolved = inetEndpoint.getResolved();
        resolved.ifPresent(System.out::println);
    }
}