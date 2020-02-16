package com.boomi.flow.services.gsuite;

import com.google.api.services.admin.directory.DirectoryScopes;
import com.manywho.sdk.services.servers.Server;
import com.manywho.sdk.services.servers.Servlet3Server;
import com.manywho.sdk.services.servers.undertow.UndertowServer;

import java.util.Arrays;
import java.util.List;

public class Application extends Servlet3Server {

    private static final List<String> SCOPES =
            Arrays.asList(
                    DirectoryScopes.ADMIN_DIRECTORY_GROUP_READONLY,
                    DirectoryScopes.ADMIN_DIRECTORY_GROUP_MEMBER_READONLY,
                    DirectoryScopes.ADMIN_DIRECTORY_USER_READONLY
            );

    public static void main(String[] args) throws Exception {
        Server server = new UndertowServer();
        server.setApplication(Application.class);
        server.start();
    }
}
