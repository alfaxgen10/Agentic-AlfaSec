import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Executors;

public final class AgenticAlfaSecAgent {
    private static final int PORT = 8765;
    private static final String TOKEN = createToken();

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), PORT), 0);
        server.createContext("/health", exchange -> route(exchange, AgenticAlfaSecAgent::health));
        server.createContext("/scan/ports", exchange -> route(exchange, AgenticAlfaSecAgent::ports));
        server.createContext("/scan/http-headers", exchange -> route(exchange, AgenticAlfaSecAgent::headers));
        server.createContext("/scan/tls", exchange -> route(exchange, AgenticAlfaSecAgent::tls));
        server.createContext("/scan/dns", exchange -> route(exchange, AgenticAlfaSecAgent::dns));
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("Agentic AlfaSec agent is running on http://127.0.0.1:" + PORT);
        System.out.println("Session token: " + TOKEN);
        System.out.println("Default scope: localhost and 127.0.0.1 only");
    }

    private static void route(HttpExchange exchange, Handler handler) throws IOException {
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            String origin = exchange.getRequestHeaders().getFirst("Origin");
            if (origin == null || !browserAllowed(exchange)) {
                send(exchange, 403, "{\"error\":\"Origin is not allowed\"}");
                return;
            }
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, OPTIONS");
            send(exchange, 204, "");
            return;
        }
        handler.handle(exchange);
    }

    @FunctionalInterface
    private interface Handler {
        void handle(HttpExchange exchange) throws IOException;
    }

    private static String createToken() {
        byte[] bytes = new byte[24];
        new java.security.SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static boolean authorized(HttpExchange exchange) {
        String supplied = exchange.getRequestHeaders().getFirst("X-AlfaSec-Token");
        return TOKEN.equals(supplied);
    }

    private static boolean browserAllowed(HttpExchange exchange) {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        return origin == null || origin.equals("http://localhost:8000") ||
            origin.equals("http://127.0.0.1:8000") ||
            (origin.startsWith("https://") && origin.endsWith(".github.io"));
    }

    private static boolean guard(HttpExchange exchange) throws IOException {
        if (!browserAllowed(exchange)) {
            send(exchange, 403, "{\"error\":\"Origin is not allowed\"}");
            return false;
        }
        if (!authorized(exchange)) {
            send(exchange, 401, "{\"error\":\"Valid X-AlfaSec-Token header required\"}");
            return false;
        }
        return true;
    }

    private static void health(HttpExchange exchange) throws IOException {
        if (!guard(exchange)) return;
        send(exchange, 200, "{\"agent\":\"Agentic AlfaSec\",\"status\":\"ready\",\"scope\":\"loopback-only\",\"time\":\"" + Instant.now() + "\"}");
    }

    private static void ports(HttpExchange exchange) throws IOException {
        if (!guard(exchange)) return;
        Map<String, String> params = query(exchange.getRequestURI().getRawQuery());
        String host = params.getOrDefault("host", "127.0.0.1");
        int start = integer(params.getOrDefault("start", "1"));
        int end = integer(params.getOrDefault("end", "1024"));
        if (!isLoopback(host) || start < 1 || end > 65535 || end < start || end - start > 256) {
            send(exchange, 400, "{\"error\":\"Only localhost targets and a maximum 256-port range are allowed\"}");
            return;
        }
        List<Integer> open = new ArrayList<>();
        for (int port = start; port <= end; port++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), 250);
                open.add(port);
            } catch (IOException ignored) { }
        }
        send(exchange, 200, "{\"host\":\"" + json(host) + "\",\"start\":" + start + ",\"end\":" + end + ",\"openPorts\":" + integers(open) + "}");
    }

    private static void headers(HttpExchange exchange) throws IOException {
        if (!guard(exchange)) return;
        Map<String, String> params = query(exchange.getRequestURI().getRawQuery());
        URI target = safeLocalUri(params.get("url"));
        if (target == null) {
            send(exchange, 400, "{\"error\":\"Use an http:// or https:// localhost URL\"}");
            return;
        }
        try {
            HttpURLConnection connection = (HttpURLConnection) target.toURL().openConnection();
            connection.setConnectTimeout(2000);
            connection.setReadTimeout(3000);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("HEAD");
            int status = connection.getResponseCode();
            Map<String, List<String>> fields = connection.getHeaderFields();
            List<String> missing = new ArrayList<>();
            for (String name : Arrays.asList("Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy")) {
                if (fields == null || !fields.keySet().stream().filter(Objects::nonNull).anyMatch(key -> key.equalsIgnoreCase(name))) missing.add(name);
            }
            send(exchange, 200, "{\"url\":\"" + json(target.toString()) + "\",\"status\":" + status + ",\"missingHeaders\":" + strings(missing) + "}");
        } catch (IOException e) {
            send(exchange, 502, "{\"error\":\"Could not connect to the authorized localhost URL\"}");
        }
    }

    private static void tls(HttpExchange exchange) throws IOException {
        if (!guard(exchange)) return;
        Map<String, String> params = query(exchange.getRequestURI().getRawQuery());
        String host = params.getOrDefault("host", "127.0.0.1");
        int port = integer(params.getOrDefault("port", "443"));
        if (!isLoopback(host) || port < 1 || port > 65535) {
            send(exchange, 400, "{\"error\":\"Only localhost TLS targets are allowed\"}");
            return;
        }
        try {
            SSLContext context = SSLContext.getDefault();
            try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket()) {
                socket.connect(new InetSocketAddress(host, port), 2000);
                socket.startHandshake();
                X509Certificate certificate = (X509Certificate) socket.getSession().getPeerCertificates()[0];
                send(exchange, 200, "{\"host\":\"" + json(host) + "\",\"port\":" + port + ",\"protocol\":\"" + json(socket.getSession().getProtocol()) + "\",\"subject\":\"" + json(certificate.getSubjectX500Principal().getName()) + "\",\"expires\":\"" + certificate.getNotAfter().toInstant() + "\"}");
            }
        } catch (Exception e) {
            send(exchange, 502, "{\"error\":\"TLS handshake failed for the authorized localhost target\"}");
        }
    }

    private static void dns(HttpExchange exchange) throws IOException {
        if (!guard(exchange)) return;
        String host = query(exchange.getRequestURI().getRawQuery()).getOrDefault("host", "localhost");
        if (!isLoopback(host) && !host.equalsIgnoreCase("localhost")) {
            send(exchange, 400, "{\"error\":\"DNS checks are limited to localhost by default\"}");
            return;
        }
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            List<String> values = new ArrayList<>();
            for (InetAddress address : addresses) values.add(address.getHostAddress());
            send(exchange, 200, "{\"host\":\"" + json(host) + "\",\"addresses\":" + strings(values) + "}");
        } catch (UnknownHostException e) {
            send(exchange, 404, "{\"error\":\"Host could not be resolved\"}");
        }
    }

    private static URI safeLocalUri(String value) {
        if (value == null) return null;
        try {
            URI uri = URI.create(value);
            if (!("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))) return null;
            return isLoopback(uri.getHost()) ? uri : null;
        } catch (IllegalArgumentException e) { return null; }
    }

    private static boolean isLoopback(String host) {
        if (host == null) return false;
        try { return InetAddress.getByName(host).isLoopbackAddress(); }
        catch (UnknownHostException e) { return false; }
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> values = new HashMap<>();
        if (raw == null) return values;
        for (String part : raw.split("&")) {
            String[] pair = part.split("=", 2);
            if (pair.length == 2) values.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8), URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
        }
        return values;
    }

    private static int integer(String value) {
        try { return Integer.parseInt(value); } catch (NumberFormatException e) { return -1; }
    }
    private static String json(String value) { return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n"); }
    private static String integers(List<Integer> values) { return values.toString(); }
    private static String strings(List<String> values) { return "[" + values.stream().map(value -> "\"" + json(value) + "\"").reduce((a, b) -> a + "," + b).orElse("") + "]"; }
    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", exchange.getRequestHeaders().getFirst("Origin") == null ? "null" : exchange.getRequestHeaders().getFirst("Origin"));
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "X-AlfaSec-Token, Content-Type");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) { output.write(bytes); }
    }
}
