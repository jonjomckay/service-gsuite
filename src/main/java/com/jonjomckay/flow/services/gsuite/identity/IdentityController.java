package com.jonjomckay.flow.services.gsuite.identity;

import com.jonjomckay.flow.services.gsuite.ApplicationConfiguration;
import com.manywho.sdk.api.run.elements.type.ObjectDataRequest;
import com.manywho.sdk.api.run.elements.type.ObjectDataResponse;
import com.manywho.sdk.api.security.AuthenticatedWho;
import com.manywho.sdk.api.security.AuthenticatedWhoResult;
import com.manywho.sdk.api.security.AuthenticationCredentials;
import com.manywho.sdk.services.configuration.ConfigurationParser;
import com.manywho.sdk.services.controllers.AbstractIdentityController;
import com.manywho.sdk.services.types.TypeBuilder;
import com.manywho.sdk.services.types.system.$User;
import com.manywho.sdk.services.types.system.AuthorizationAttribute;
import com.manywho.sdk.services.types.system.AuthorizationGroup;
import com.manywho.sdk.services.types.system.AuthorizationUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.List;

@Path("/")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class IdentityController extends AbstractIdentityController {
    private final static Logger LOGGER = LoggerFactory.getLogger(IdentityController.class);

    private final ConfigurationParser configurationParser;
    private final TypeBuilder typeBuilder;
    private final Provider<AuthenticatedWho> authenticatedWhoProvider;
    private final IdentityManager manager;

    @Inject
    public IdentityController(ConfigurationParser configurationParser, TypeBuilder typeBuilder, Provider<AuthenticatedWho> authenticatedWhoProvider, IdentityManager manager) {
        this.configurationParser = configurationParser;
        this.typeBuilder = typeBuilder;
        this.authenticatedWhoProvider = authenticatedWhoProvider;
        this.manager = manager;
    }

    @Override
    public AuthenticatedWhoResult authentication(AuthenticationCredentials authenticationCredentials) {
        ApplicationConfiguration configuration = configurationParser.from(authenticationCredentials);

        return manager.authentication(authenticationCredentials, configuration);
    }

    @Override
    public ObjectDataResponse authorization(ObjectDataRequest objectDataRequest) {
        AuthenticatedWho authenticatedWho = authenticatedWhoProvider.get();

        ApplicationConfiguration configuration = configurationParser.from(objectDataRequest);

        $User user = manager.authorization(authenticatedWho, objectDataRequest, configuration);

        return new ObjectDataResponse(typeBuilder.from(user));
    }

    @Path("/authorization/group/attribute")
    @POST
    public ObjectDataResponse groupAttributes(ObjectDataRequest objectDataRequest) {
        List<AuthorizationAttribute> attributes = manager.groupAttributes(objectDataRequest);

        return new ObjectDataResponse(typeBuilder.from(attributes));
    }

    @Path("/authorization/group")
    @POST
    public ObjectDataResponse groups(ObjectDataRequest objectDataRequest) {
        ApplicationConfiguration configuration = configurationParser.from(objectDataRequest);

        List<AuthorizationGroup> groups = manager.groups(objectDataRequest, configuration);

        return new ObjectDataResponse(typeBuilder.from(groups));
    }

    @Path("/authorization/user/attribute")
    @POST
    public ObjectDataResponse userAttributes(ObjectDataRequest objectDataRequest) {
        List<AuthorizationAttribute> attributes = manager.userAttributes(objectDataRequest);

        return new ObjectDataResponse(typeBuilder.from(attributes));
    }

    @Path("/authorization/user")
    @POST
    public ObjectDataResponse users(ObjectDataRequest objectDataRequest) {
        ApplicationConfiguration configuration = configurationParser.from(objectDataRequest);

        List<AuthorizationUser> users = manager.users(objectDataRequest, configuration);

        return new ObjectDataResponse(typeBuilder.from(users));
    }
}
