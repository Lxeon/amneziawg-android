/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package org.amnezia.awg.config;

import android.util.Log;
import androidx.annotation.Nullable;
import org.amnezia.awg.util.NonNullForAll;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * An external endpoint (host and port) used to connect to an AmneziaWG {@link Peer}.
 * <p>
 * Instances of this class are externally immutable.
 */
@NonNullForAll
public final class InetEndpoint {
    private static final Pattern BARE_IPV6 = Pattern.compile("^[^\\[\\]]*:[^\\[\\]]*");
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");
    private static final String TAG = "AmneziaWG/InetEndpoint";

    private final String host;
    private final boolean isResolved;
    private final Object lock = new Object();
    private final int port;
    private Instant lastResolution = Instant.EPOCH;
    @Nullable
    private InetEndpoint resolved;

    private InetEndpoint(final String host, final boolean isResolved, final int port) {
        this.host = host;
        this.isResolved = isResolved;
        this.port = port;
    }

    public static InetEndpoint parse(final String endpoint) throws ParseException {
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(InetEndpoint.class, endpoint, "Forbidden characters");

        final URI uri;
        try {
            uri = new URI("awg://" + endpoint);
        } catch (final URISyntaxException e) {
            throw new ParseException(InetEndpoint.class, endpoint, e);
        }

        if (uri.getPort() < 0 || uri.getPort() > 65535)
            throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");

        try {
            InetAddresses.parse(uri.getHost());
            // Parsing ths host as a numeric address worked, so we don't need to do DNS lookups.
            return new InetEndpoint(uri.getHost(), true, uri.getPort());
        } catch (final ParseException ignored) {
            // Failed to parse the host as a numeric address, so it must be a DNS hostname/FQDN.
            return new InetEndpoint(uri.getHost(), false, uri.getPort());
        }
    }

    /**
     * Generate an {@code InetEndpoint} instance with the same port and the host resolved using DNS
     * to a numeric address. If the host is already numeric, the existing instance may be returned.
     * Because this function may perform network I/O, it must not be called from the main thread.
     *
     * @return the resolved endpoint, or {@link Optional#empty()}
     */
    public Optional<InetEndpoint> getResolved() {
        if (isResolved) {
            Log.i(TAG, "Endpoint resolved -> " + this);
            return Optional.of(this);
        }

        synchronized (lock) {
            if (Duration.between(lastResolution, Instant.now()).toMinutes() > 1) {
                // 优先顺序：SRV -> TXT -> IP4P -> 普通DNS解析
                Optional<InetEndpoint> resolvedOpt;

                // 1. SRV
                resolvedOpt = resolveViaSrv(host);
                if (resolvedOpt.isPresent()) {
                    Log.i(TAG, "[DNS] SRV record find, wait for next resolve");
                    resolved = resolvedOpt.get();
                    lastResolution = Instant.now();
                    return resolvedOpt;
                }

                // 2. TXT
                resolvedOpt = resolveViaTxt(host);
                if (resolvedOpt.isPresent()) {
                    Log.i(TAG, "[DNS] TXT record find, wait for next resolve");
                    resolved = resolvedOpt.get();
                    lastResolution = Instant.now();
                    return resolvedOpt;
                }

                try {
                    InetAddress[] candidates = InetAddress.getAllByName(host);
                    InetAddress selected = candidates[0];

                    for (InetAddress addr : candidates) {
                        if (addr instanceof Inet4Address) {
                            selected = addr;
                            break;
                        }
                    }

                    // 3. IP4P
                    Optional<InetEndpoint> resolvedIp4p = resolveIp4p(selected);
                    if (resolvedIp4p.isPresent()) {
                        Log.i(TAG, "[DNS] ip4p record find");
                        resolved = resolvedIp4p.get();
                        lastResolution = Instant.now();
                        return resolvedIp4p;
                    }

                    // 4. ipv4/ipv6
                    if (resolved == null && selected.getHostAddress() != null) {
                        resolved = new InetEndpoint(selected.getHostAddress(), true, port);
                    }

                    lastResolution = Instant.now();
                } catch (UnknownHostException ignored) {
                    resolved = null;
                }
            }

            return Optional.ofNullable(resolved);
        }
    }

    private Optional<InetEndpoint> resolveIp4p(InetAddress address) throws UnknownHostException {
        if (address instanceof Inet6Address) {
            byte[] v6 = address.getAddress();
            if ((v6[0] == 0x20) && (v6[1] == 0x01) && (v6[2] == 0x00) && (v6[3] == 0x00)) {
                InetAddress v4 = InetAddress.getByAddress(Arrays.copyOfRange(v6, 12, 16));
                int p = ((v6[10] & 0xFF) << 8) | (v6[11] & 0xFF);
                return Optional.of(new InetEndpoint(Objects.requireNonNull(v4.getHostAddress()), true, p));
            }
        }
        return Optional.empty();
    }

    private Optional<InetEndpoint> resolveViaSrv(String domain) {
        try {
            Lookup lookup = new Lookup(domain, Type.SRV);
            lookup.setCache(null);
            lookup.setResolver(new SimpleResolver("223.5.5.5"));
            Record[] records = lookup.run();
            if (records != null && records.length > 0) {
                SRVRecord srv = (SRVRecord) records[0];
                String targetHost = srv.getTarget().toString(true); // 去掉尾部的点
                int port = srv.getPort();
                return Optional.of(new InetEndpoint(targetHost, false, port));
            }
        } catch (TextParseException | UnknownHostException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return Optional.empty();
    }

    private Optional<InetEndpoint> resolveViaTxt(String domain) {
        try {
            Lookup lookup = new Lookup(domain, Type.TXT);
            lookup.setCache(null);
            lookup.setResolver(new SimpleResolver("223.5.5.5"));
            Record[] records = lookup.run();
            if (records != null) {
                for (Record record : records) {
                    TXTRecord txt = (TXTRecord) record;
                    for (Object s : txt.getStrings()) {
                        String str = s.toString();
                        if (str.matches("^[^:]+:\\d{1,5}$")) {
                            String[] parts = str.split(":");
                            return Optional.of(new InetEndpoint(parts[0], false, Integer.parseInt(parts[1])));
                        }
                    }
                }
            }
        } catch (TextParseException | NumberFormatException | UnknownHostException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return Optional.empty();
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof InetEndpoint other))
            return false;
        return host.equals(other.host) && port == other.port;
    }

    @Override
    public int hashCode() {
        return host.hashCode() ^ port;
    }

    @Override
    public String toString() {
        final boolean isBareIpv6 = isResolved && BARE_IPV6.matcher(host).matches();
        return (isBareIpv6 ? '[' + host + ']' : host) + ':' + port;
    }
}
