# 避免加载 JNA/JNDI 服务
-assumenosideeffects class java.util.ServiceLoader {
    public static java.util.ServiceLoader load(java.lang.Class);
    public static java.util.ServiceLoader load(java.lang.Class, java.lang.ClassLoader);
}

# 忽略这些类的警告（不建议在生产使用 JNA）
-dontwarn javax.naming.**
-dontwarn com.sun.jna.**
-dontwarn org.xbill.DNS.config.**

# 保留你用到的 DNS 类
-keep class org.xbill.DNS.Lookup { *; }
-keep class org.xbill.DNS.Record { *; }
-keep class org.xbill.DNS.SRVRecord { *; }
-keep class org.xbill.DNS.TXTRecord { *; }
-keep class org.xbill.DNS.TextParseException { *; }
-keep class org.xbill.DNS.Type { *; }