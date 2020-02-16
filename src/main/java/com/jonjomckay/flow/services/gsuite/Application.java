package com.jonjomckay.flow.services.gsuite;

import com.manywho.sdk.services.servers.Server;
import com.manywho.sdk.services.servers.Servlet3Server;
import com.manywho.sdk.services.servers.undertow.UndertowServer;

public class Application extends Servlet3Server {
    public static void main(String[] args) throws Exception {
        Server server = new UndertowServer();
        server.setApplication(Application.class);
        server.start();
    }
}
