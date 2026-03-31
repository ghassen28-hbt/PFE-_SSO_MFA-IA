package tn.pfe.kc;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class RiskEventListenerProvider implements EventListenerProvider {

    private final KeycloakSession session;
    private final String collectorUrl;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Set<EventType> TRACKED = Set.of(
            EventType.LOGIN,
            EventType.LOGIN_ERROR,
            EventType.LOGOUT,
            EventType.UPDATE_PASSWORD,
            EventType.UPDATE_TOTP,
            EventType.REMOVE_TOTP,
            EventType.REGISTER
    );

    public RiskEventListenerProvider(KeycloakSession session, String collectorUrl) {
        this.session = session;
        this.collectorUrl = collectorUrl;
    }

    @Override
    public void onEvent(Event event) {
        if (event == null || event.getType() == null || !TRACKED.contains(event.getType())) {
            return;
        }

        try {
            String realmName = "unknown";
            try {
                if (session != null
                        && session.getContext() != null
                        && session.getContext().getRealm() != null) {
                    realmName = session.getContext().getRealm().getName();
                }
            } catch (Exception ignored) {
            }

            // IP "native" vue par Keycloak
            String eventIp = safe(event.getIpAddress());

            String userAgent = "";
            String xForwardedFor = "";
            String xRealIp = "";

            try {
                if (session != null
                        && session.getContext() != null
                        && session.getContext().getHttpRequest() != null
                        && session.getContext().getHttpRequest().getHttpHeaders() != null) {

                    userAgent = safe(session.getContext()
                            .getHttpRequest()
                            .getHttpHeaders()
                            .getHeaderString("User-Agent"));

                    xForwardedFor = safe(session.getContext()
                            .getHttpRequest()
                            .getHttpHeaders()
                            .getHeaderString("X-Forwarded-For"));

                    xRealIp = safe(session.getContext()
                            .getHttpRequest()
                            .getHttpHeaders()
                            .getHeaderString("X-Real-IP"));
                }
            } catch (Exception ignored) {
            }

            // Choix de la meilleure IP à envoyer
            String finalIp = chooseBestIp(eventIp, xForwardedFor, xRealIp);

            String username = "";
            if (event.getDetails() != null) {
                username = safe(event.getDetails().getOrDefault("username", ""));
            }

            Map<String, Object> payload = new HashMap<>();
            payload.put("ts", Instant.ofEpochMilli(event.getTime()).toString());
            payload.put("realm", realmName);
            payload.put("type", event.getType().name());
            payload.put("clientId", safe(event.getClientId()));
            payload.put("userId", safe(event.getUserId()));
            payload.put("username", username);
            payload.put("sessionId", safe(event.getSessionId()));

            // On garde les 3 infos pour debug côté collector
            payload.put("ipAddress", finalIp);
            payload.put("event_ip", eventIp);
            payload.put("http_x_forwarded_for", xForwardedFor);
            payload.put("http_x_real_ip", xRealIp);

            payload.put("error", safe(event.getError()));
            payload.put("details", event.getDetails() != null ? event.getDetails() : Map.of());
            payload.put("http_user_agent", userAgent);

            System.out.println("[RiskListener] DEBUG event.getIpAddress() = " + eventIp);
            System.out.println("[RiskListener] DEBUG X-Forwarded-For = " + xForwardedFor);
            System.out.println("[RiskListener] DEBUG X-Real-IP = " + xRealIp);
            System.out.println("[RiskListener] DEBUG finalIp = " + finalIp);
            System.out.println("[RiskListener] DEBUG collectorUrl = " + collectorUrl);
            System.out.println("[RiskListener] DEBUG payload = " + MAPPER.writeValueAsString(payload));

            sendToCollector(payload);

        } catch (Exception e) {
            System.err.println("[RiskListener] onEvent error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        // Optionnel pour plus tard
    }

    @Override
    public void close() {
        // Rien à fermer
    }

    private void sendToCollector(Map<String, Object> payload) {
        HttpURLConnection conn = null;
        try {
            String json = MAPPER.writeValueAsString(payload);

            URL url = new URL(collectorUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");

            byte[] out = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(out);
                os.flush();
            }

            int code = conn.getResponseCode();
            if (code < 200 || code >= 300) {
                System.err.println("[RiskListener] Collector returned HTTP " + code);
            } else {
                System.out.println("[RiskListener] Collector returned HTTP " + code);
            }

        } catch (Exception e) {
            System.err.println("[RiskListener] Send failed: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private String chooseBestIp(String eventIp, String xForwardedFor, String xRealIp) {
        // 1) Priorité à X-Forwarded-For si présent
        if (!xForwardedFor.isEmpty()) {
            String first = xForwardedFor.split(",")[0].trim();
            if (!first.isEmpty()) {
                return first;
            }
        }

        // 2) Puis X-Real-IP
        if (!xRealIp.isEmpty()) {
            return xRealIp.trim();
        }

        // 3) Sinon IP native de l'événement
        return eventIp;
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }
}