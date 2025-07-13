/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package org.amnezia.awg.config;

import android.util.Log;
import androidx.annotation.Nullable;
import org.amnezia.awg.util.NonNullForAll;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DohResolver;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
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
    private static final Pattern SRV_PATTERN = Pattern.compile(
            "^_[a-zA-Z0-9-]+\\._(tcp|udp|\\w+)\\.[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*\\.[a-zA-Z]{2,}\\.?$"
    );
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");
    private static final String TAG = "AmneziaWG/InetEndpoint";

    private final String host;
    private final boolean isResolved;
    private final Object lock = new Object();
    private final int port;
    private final int resolveTimes = 5;
    private Instant lastResolution = Instant.EPOCH;
    @Nullable
    private InetEndpoint resolved;

    private InetEndpoint(final String host, final boolean isResolved, final int port) {
        this.host = host;
        this.isResolved = isResolved;
        this.port = port;
    }

    int resolveCount = 0;

    public static InetEndpoint parse(final String endpoint) throws ParseException {
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(InetEndpoint.class, endpoint, "Forbidden characters");

        URI uri = null;
        try {

            // check srv domain host, _wireguard._udp.example.com
            String[] parts = endpoint.split(":");
            if (parts.length == 2 && isSrvDomain(parts[0])) {
                InetEndpoint t = new InetEndpoint("", false, Integer.parseInt(parts[1]));

                Optional<InetEndpoint> opt = t.startResolve(parts[0]);
                if (opt.isEmpty()) {
                    throw new ParseException(InetEndpoint.class, endpoint, "Invalid srv domain");
                }
                t = opt.get();
                uri = new URI("awg://" + t.getHost() + ":" + t.getPort());
            }

            if (uri == null) {
                uri = new URI("awg://" + endpoint);

            }
        } catch (final Exception e) {
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

    public static boolean isSrvDomain(String domain) {
        domain = domain.trim();
        if (domain.isEmpty()) {
            return false;
        }
        return SRV_PATTERN.matcher(domain).matches();
    }

    private static Lookup getLookup(String domain, int type) {
        Lookup lookup = null;
        try {
            lookup = new Lookup(domain, type);
        } catch (TextParseException e) {
            throw new RuntimeException(e);
        }
        lookup.setCache(null);
        Resolver[] resolvers = new Resolver[2];
        resolvers[0] = new DohResolver("https://223.5.5.5/dns-query");
        resolvers[1] = new DohResolver("https://doh.360.cn/dns-query");
        ExtendedResolver exResolver = new ExtendedResolver(resolvers);
        lookup.setResolver(exResolver);
        return lookup;
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
                return startResolve(host);
            }

            return Optional.ofNullable(resolved);
        }
    }

    private Optional<InetEndpoint> startResolve(String host) {
        int port = this.port;
        if (resolved != null) {
            port = resolved.port;
        }
        resolveCount++;
        if (!isResolved && resolveCount > resolveTimes) {
            Log.w(TAG, "[DNS] Resolving " + host + " too many times");
            return Optional.empty();
        }
        // 优先顺序：SRV -> TXT -> IP4P -> 普通DNS解析
        Optional<InetEndpoint> opt;

        // 1. SRV
        opt = resolveSrv(host);
        if (opt.isPresent()) {
            Log.i(TAG, "[DNS] SRV record find, wait for next resolve");
            resolved = opt.get();
        }
        if (resolved != null) {
            host = resolved.host;
            port = resolved.port;
        }

        // 2. TXT
        opt = resolveTxt(host);
        if (opt.isPresent()) {
            Log.i(TAG, "[DNS] TXT record find, wait for next resolve");
            resolved = opt.get();
            if (resolved.isResolved) {
                return Optional.of(resolved);
            }
        }
        if (resolved != null) {
            host = resolved.host;
            port = resolved.port;
        }

        // 先不急着返回，看看是不是还有域名
        try {

            // ipv4
            Optional<InetAddress> optIp = resolveIpv4(host);

            if (optIp.isPresent()) {
                InetAddress addr = optIp.get();
                resolved = new InetEndpoint(Objects.requireNonNull(addr.getHostAddress()), true, port);
                lastResolution = Instant.now();
                return Optional.of(resolved);
            }

            optIp = resolveIpv6(host);
            if (optIp.isPresent()) {
                InetAddress addr = optIp.get();

                // 3. IP4P
                opt = resolveIp4p(addr);
                if (opt.isPresent()) {
                    Log.i(TAG, "[DNS] ip4p record find");
                    resolved = opt.get();
                    lastResolution = Instant.now();
                    return Optional.of(resolved);
                }

                resolved = new InetEndpoint(Objects.requireNonNull(addr.getHostAddress()), true, port);
                lastResolution = Instant.now();
                return Optional.of(resolved);
            }

            if (!resolved.isResolved) {
                // 递归查询，srv和txt记录仍然可能是域名
                startResolve(resolved.host);
            }

        } catch (UnknownHostException ignored) {
            resolved = null;
        }
        return Optional.ofNullable(resolved);
    }

    private Optional<InetAddress> resolveIpv4(String domain) {
        Lookup lookup = getLookup(domain, Type.A);
        Record[] records = lookup.run();

        if (records == null || records.length == 0) {
            return Optional.empty();
        }

        ARecord a = (ARecord) records[0];
        InetAddress target = a.getAddress();
        return Optional.of(target);
    }

    private Optional<InetAddress> resolveIpv6(String domain) {
        Lookup lookup = getLookup(domain, Type.AAAA);
        Record[] records = lookup.run();

        if (records == null || records.length == 0) {
            return Optional.empty();
        }

        AAAARecord a = (AAAARecord) records[0];
        InetAddress target = a.getAddress();
        return Optional.of(target);
    }

    private Optional<InetEndpoint> resolveSrv(String domain) {
        Lookup lookup = getLookup(domain, Type.SRV);
        Record[] records = lookup.run();

        if (records == null || records.length == 0) {
            return Optional.empty();
        }

        SRVRecord srv = (SRVRecord) records[0];
        String targetHost = srv.getTarget().toString(true); // 去掉尾部的点
        int port = srv.getPort();
        return Optional.of(new InetEndpoint(targetHost, false, port));
    }

    private Optional<InetEndpoint> resolveTxt(String domain) {
        try {
            Lookup lookup = getLookup(domain, Type.TXT);
            Record[] records = lookup.run();
            if (records == null || records.length == 0) {
                return Optional.empty();
            }
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
        } catch (NumberFormatException e) {
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
