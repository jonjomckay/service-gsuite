package com.boomi.flow.services.gsuite;

import com.manywho.sdk.api.ContentType;
import com.manywho.sdk.services.configuration.Configuration;
import com.boomi.flow.services.gsuite.types.Domain;

import java.util.ArrayList;
import java.util.List;

public class ApplicationConfiguration implements Configuration {
    @Configuration.Setting(name = "Client ID", contentType = ContentType.String)
    private String clientId;

    @Configuration.Setting(name = "Client Secret", contentType = ContentType.Password)
    private String clientSecret;

    @Configuration.Setting(name = "Domains", contentType = ContentType.List)
    private List<Domain> domains = new ArrayList<>();

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public List<Domain> getDomains() {
        return domains;
    }
}
