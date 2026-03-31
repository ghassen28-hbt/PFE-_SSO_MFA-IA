package tn.pfe.kc;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class RiskEventListenerProviderFactory implements EventListenerProviderFactory {

    public static final String ID = "risk-event-listener";
    private String collectorUrl;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new RiskEventListenerProvider(session, collectorUrl);
    }

    @Override
    public void init(Config.Scope config) {
        String env = System.getenv("PFE_COLLECTOR_URL");
        this.collectorUrl = (env != null && !env.isBlank())
                ? env
                : "http://event-collector:8088/events";

        System.out.println("[RiskListener] Started -> " + collectorUrl);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Rien pour le moment
    }

    @Override
    public void close() {
        // Rien à fermer
    }

    @Override
    public String getId() {
        return ID;
    }
}