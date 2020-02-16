package com.boomi.flow.services.gsuite.identity;

import com.boomi.flow.services.gsuite.ApplicationConfiguration;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.admin.directory.Directory;
import com.google.api.services.admin.directory.model.Group;
import com.google.api.services.admin.directory.model.Groups;
import com.google.api.services.admin.directory.model.User;
import com.google.api.services.oauth2.Oauth2;
import com.google.api.services.oauth2.model.Userinfoplus;
import com.google.common.base.MoreObjects;
import com.manywho.sdk.api.AuthorizationType;
import com.manywho.sdk.api.run.ServiceProblemException;
import com.manywho.sdk.api.run.elements.config.Authorization;
import com.manywho.sdk.api.run.elements.type.MObject;
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
import org.apache.commons.collections.CollectionUtils;
import org.apache.http.client.utils.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Path("/")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class IdentityController extends AbstractIdentityController {
    private final static Logger LOGGER = LoggerFactory.getLogger(IdentityController.class);

    private final static HttpTransport httpTransport = new NetHttpTransport();
    private final static JacksonFactory jsonFactory = new JacksonFactory();

    private final ConfigurationParser configurationParser;
    private final TypeBuilder typeBuilder;
    private final Provider<AuthenticatedWho> authenticatedWhoProvider;

    @Inject
    public IdentityController(ConfigurationParser configurationParser, TypeBuilder typeBuilder, Provider<AuthenticatedWho> authenticatedWhoProvider) {
        this.configurationParser = configurationParser;
        this.typeBuilder = typeBuilder;
        this.authenticatedWhoProvider = authenticatedWhoProvider;
    }

    // TODO
    private static Directory createDirectory(ApplicationConfiguration configuration) {
        GoogleCredential credential = new GoogleCredential.Builder()
                .setClientSecrets(configuration.getClientId(), configuration.getClientSecret())
                .setJsonFactory(jsonFactory)
                .setTransport(httpTransport)
                .build();

        return new Directory.Builder(httpTransport, jsonFactory, credential)
                .setApplicationName("Boomi Flow")
                .build();
    }

    @Override
    public AuthenticatedWhoResult authentication(AuthenticationCredentials authenticationCredentials) throws Exception {
        ApplicationConfiguration configuration = configurationParser.from(authenticationCredentials);

        GoogleAuthorizationCodeFlow googleAuthorizationCodeFlow = new GoogleAuthorizationCodeFlow.Builder(httpTransport, jsonFactory, configuration.getClientId(), configuration.getClientSecret(), Arrays.asList("email", "openid", "profile"))
                .build();

        try {
            GoogleTokenResponse tokenResponse = googleAuthorizationCodeFlow
                    .newTokenRequest(authenticationCredentials.getCode())
                    .setRedirectUri(authenticationCredentials.getRedirectUri())
                    .execute();

            GoogleCredential credential = new GoogleCredential()
                    .setFromTokenResponse(tokenResponse);

            Oauth2 oauth2 = new Oauth2.Builder(httpTransport, jsonFactory, credential)
                    .setApplicationName("Boomi Flow")
                    .build();

            Userinfoplus userInfo = oauth2.userinfo()
                    .get()
                    .execute();

            // Ensure user is part of any given hosted domain
            // TODO: This doesn't work due to a bug where list configuration values aren't sent
//            boolean isUserNotMemberOfDomain = configuration.getDomains()
//                    .stream()
//                    .noneMatch(domain -> domain.getDomain().equals(userInfo.getHd()));
//
//            if (isUserNotMemberOfDomain) {
//                return AuthenticatedWhoResult.createDeniedResult("You are not a member of one of the specified G Suite domains");
//            }

            AuthenticatedWhoResult authenticatedWhoResult = new AuthenticatedWhoResult();
            authenticatedWhoResult.setDirectoryId(MoreObjects.firstNonNull(userInfo.getHd(), "Google"));
            authenticatedWhoResult.setDirectoryName(MoreObjects.firstNonNull(userInfo.getHd(), "Google"));
            authenticatedWhoResult.setEmail(userInfo.getEmail());
            authenticatedWhoResult.setFirstName(userInfo.getGivenName());
            authenticatedWhoResult.setLastName(userInfo.getFamilyName());
            authenticatedWhoResult.setStatus(AuthenticatedWhoResult.AuthenticationStatus.Authenticated);
            authenticatedWhoResult.setToken(tokenResponse.toString());
            authenticatedWhoResult.setUserId(userInfo.getId());
            authenticatedWhoResult.setUsername(userInfo.getEmail());

            return authenticatedWhoResult;
        } catch (TokenResponseException e) {
            LOGGER.error("There was an error with the token response while authenticating the user", e);

            AuthenticatedWhoResult authenticatedWhoResult = new AuthenticatedWhoResult();
            authenticatedWhoResult.setStatus(AuthenticatedWhoResult.AuthenticationStatus.AccessDenied);
            authenticatedWhoResult.setStatusMessage(String.format("An error occurred retrieving the token from Google: %s", e.getDetails().getError()));

            return authenticatedWhoResult;
        } catch (Exception e) {
            LOGGER.error("There was an unknown error when authenticating the user", e);

            AuthenticatedWhoResult authenticatedWhoResult = new AuthenticatedWhoResult();
            authenticatedWhoResult.setStatus(AuthenticatedWhoResult.AuthenticationStatus.AccessDenied);
            authenticatedWhoResult.setStatusMessage(e.getMessage());

            return authenticatedWhoResult;
        }
    }

    @Override
    public ObjectDataResponse authorization(ObjectDataRequest objectDataRequest) throws Exception {
        // TODO: Validate objectDataRequest.getAuthorization()

        AuthenticatedWho authenticatedWho = authenticatedWhoProvider.get();

        ApplicationConfiguration configuration = configurationParser.from(objectDataRequest);

        String status = getAuthorizationStatus(configuration, authenticatedWho, objectDataRequest.getAuthorization());

        URI uri = new URIBuilder()
                .setScheme("https")
                .setHost("accounts.google.com")
                .setPath("/o/oauth2/auth")
                .addParameter("approval_prompt", "force")
                .addParameter("client_id", configuration.getClientId())
                .addParameter("response_type", "code")
                .addParameter("scope", "email openid profile")
                .build();

        List<MObject> objectData = typeBuilder.from(createUserObject(authenticatedWho, uri.toString(), status));

        return new ObjectDataResponse(objectData);
    }

    private $User createUserObject(AuthenticatedWho authenticatedWho, String loginUrl, String status) {
        $User user = new $User();

        if (authenticatedWho.getUserId().equals("PUBLIC_USER")) {
            user.setDirectoryId("Google");
            user.setDirectoryName("Google");
            user.setLoginUrl(loginUrl);
            user.setAuthenticationType(AuthorizationType.Oauth2);
            user.setStatus("401");
            user.setUserId("");
        } else {
            GoogleCredential credential;
            try {
                credential = new GoogleCredential()
                        .setFromTokenResponse(jsonFactory.fromString(authenticatedWho.getToken(), GoogleTokenResponse.class));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            Oauth2 oauth2 = new Oauth2.Builder(httpTransport, jsonFactory, credential)
                    .setApplicationName("Boomi Flow")
                    .build();

            Userinfoplus userInfo;
            try {
                userInfo = oauth2.userinfo()
                        .get()
                        .execute();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            user.setDirectoryId(MoreObjects.firstNonNull(userInfo.getHd(), "Google"));
            user.setDirectoryName(MoreObjects.firstNonNull(userInfo.getHd(), "Google"));
            user.setEmail(userInfo.getEmail());
            user.setFirstName(userInfo.getGivenName());
            user.setLastName(userInfo.getFamilyName());
            user.setLoginUrl(loginUrl);
            user.setAuthenticationType(AuthorizationType.Oauth2);
            user.setStatus(status);
            user.setUserId(userInfo.getId());
            user.setUsername(userInfo.getEmail());
        }

        return user;
    }

    private String getAuthorizationStatus(ApplicationConfiguration configuration, AuthenticatedWho user, Authorization authorization) {
        GoogleCredential credential;

        Directory directory = createDirectory(configuration);

        switch (authorization.getGlobalAuthenticationType()) {
            case Public:
                return "200";
            case AllUsers:
                if (user.getUserId().equalsIgnoreCase("PUBLIC_USER")) {
                    return "401";
                }

                try {
                    credential = new GoogleCredential()
                            .setFromTokenResponse(jsonFactory.fromString(user.getToken(), GoogleTokenResponse.class));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                // If our current token has expired, send back a 401
                if (credential.getExpiresInSeconds() <= 0) {
                    return "401";
                }

                return "200";

            case Specified:
                if (user.getUserId().equalsIgnoreCase("PUBLIC_USER")) {
                    return "401";
                }

                try {
                    credential = new GoogleCredential()
                            .setFromTokenResponse(jsonFactory.fromString(user.getToken(), GoogleTokenResponse.class));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                // If our current token has expired, send back a 401
                if (credential.getExpiresInSeconds() <= 0) {
                    return "401";
                }

                boolean validGroup = false;
                boolean validUser = false;

                if (CollectionUtils.isNotEmpty(authorization.getGroups())) {
                    Groups groups;

                    try {
                        groups = directory.groups()
                                .list()
                                .setMaxResults(200)
                                .setUserKey(user.getUserId())
                                .execute();
                    } catch (IOException e) {
                        LOGGER.error("Unable to load the groups for the user {}", user.getUserId(), e);

                        throw new ServiceProblemException(500, "Something went wrong when loading the groups from Google: " + e.getMessage());
                    }

                    // TODO: This only supports the first page of 200 groups
                    for (Group group : groups.getGroups()) {
                        validGroup = authorization.getGroups()
                                .stream()
                                .anyMatch(m -> m.getAuthenticationId().equals(group.getId()));
                    }
                }

                if (CollectionUtils.isNotEmpty(authorization.getUsers())) {
                    validUser = authorization.getUsers()
                            .stream()
                            .anyMatch(m -> m.getAuthenticationId().equals(user.getUserId()));
                }

                if (validGroup || validUser) {
                    return "200";
                }

            default:
                return "401";
        }
    }

    @Path("/authorization/group/attribute")
    @POST
    public ObjectDataResponse groupAttributes(ObjectDataRequest objectDataRequest) throws Exception {
        return new ObjectDataResponse(
                typeBuilder.from(new AuthorizationAttribute("member", "Member"))
        );
    }

    @Path("/authorization/group")
    @POST
    public ObjectDataResponse groups(ObjectDataRequest objectDataRequest) throws Exception {
        ApplicationConfiguration configuration = configurationParser.from(objectDataRequest);

        Directory directory = createDirectory(configuration);

        // Look up the groups inside all the configured domains
        Stream<Group> groups = configuration.getDomains().stream()
                .flatMap(domain -> {
                    try {
                        return directory.groups()
                                .list()
                                .setDomain(domain.getDomain())
                                .execute()
                                .getGroups()
                                .stream();
                    } catch (IOException e) {
                        throw new RuntimeException("Unable to fetch groups for the domain: " + domain.getDomain(), e);
                    }
                });

        // Map all the discovered groups into the expected types
        List<AuthorizationGroup> authorizationGroups = groups
                .map(group -> new AuthorizationGroup(group.getId(), group.getName(), group.getDescription()))
                .collect(Collectors.toList());

        return new ObjectDataResponse(typeBuilder.from(authorizationGroups));
    }

    @Path("/authorization/user/attribute")
    @POST
    public ObjectDataResponse userAttributes(ObjectDataRequest objectDataRequest) throws Exception {
        return new ObjectDataResponse(
                typeBuilder.from(new AuthorizationAttribute("user", "User"))
        );
    }

    @Path("/authorization/user")
    @POST
    public ObjectDataResponse users(ObjectDataRequest objectDataRequest) throws Exception {
        ApplicationConfiguration configuration = configurationParser.from(objectDataRequest);

        Directory directory = createDirectory(configuration);

        // Look up the users inside all the configured domains
        Stream<User> users = configuration.getDomains().stream()
                .flatMap(domain -> {
                    try {
                        return directory.users()
                                .list()
                                .setDomain(domain.getDomain())
                                .execute()
                                .getUsers()
                                .stream();
                    } catch (IOException e) {
                        throw new RuntimeException("Unable to fetch users for the domain: " + domain.getDomain(), e);
                    }
                });

        // Map all the discovered users into the expected types
        List<AuthorizationUser> authorizationUsers = users
                .map(user -> new AuthorizationUser(user.getId(), user.getName().getFullName()))
                .collect(Collectors.toList());

        return new ObjectDataResponse(typeBuilder.from(authorizationUsers));
    }
}
