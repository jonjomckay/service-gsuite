package com.jonjomckay.flow.services.gsuite.identity;

import com.jonjomckay.flow.services.gsuite.ApplicationConfiguration;
import com.google.api.client.auth.oauth2.TokenResponse;
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
import com.google.common.collect.Lists;
import com.manywho.sdk.api.AuthorizationType;
import com.manywho.sdk.api.run.ServiceProblemException;
import com.manywho.sdk.api.run.elements.config.Authorization;
import com.manywho.sdk.api.run.elements.type.ObjectDataRequest;
import com.manywho.sdk.api.security.AuthenticatedWho;
import com.manywho.sdk.api.security.AuthenticatedWhoResult;
import com.manywho.sdk.api.security.AuthenticationCredentials;
import com.manywho.sdk.services.types.system.$User;
import com.manywho.sdk.services.types.system.AuthorizationAttribute;
import com.manywho.sdk.services.types.system.AuthorizationGroup;
import com.manywho.sdk.services.types.system.AuthorizationUser;
import org.apache.commons.collections.CollectionUtils;
import org.apache.http.client.utils.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class IdentityManager {
    private final static Logger LOGGER = LoggerFactory.getLogger(IdentityManager.class);

    private final static HttpTransport httpTransport = new NetHttpTransport();
    private final static JacksonFactory jsonFactory = new JacksonFactory();

    public AuthenticatedWhoResult authentication(AuthenticationCredentials credentials, ApplicationConfiguration configuration) {
        GoogleAuthorizationCodeFlow googleAuthorizationCodeFlow = new GoogleAuthorizationCodeFlow.Builder(httpTransport, jsonFactory, configuration.getClientId(), configuration.getClientSecret(), Arrays.asList("email", "openid", "profile"))
                .build();

        try {
            GoogleTokenResponse tokenResponse = googleAuthorizationCodeFlow
                    .newTokenRequest(credentials.getCode())
                    .setRedirectUri(credentials.getRedirectUri())
                    .execute();

            Userinfoplus userInfo = getCurrentUser(tokenResponse);

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

    public $User authorization(AuthenticatedWho authenticatedWho, ObjectDataRequest objectDataRequest, ApplicationConfiguration configuration) {
        // TODO: Validate objectDataRequest.getAuthorization()

        String status = getAuthorizationStatus(configuration, authenticatedWho, objectDataRequest.getAuthorization());

        URI uri;
        try {
            uri = new URIBuilder()
                    .setScheme("https")
                    .setHost("accounts.google.com")
                    .setPath("/o/oauth2/auth")
                    .addParameter("approval_prompt", "force")
                    .addParameter("client_id", configuration.getClientId())
                    .addParameter("response_type", "code")
                    .addParameter("scope", "email openid profile")
                    .build();
        } catch (URISyntaxException e) {
            throw new ServiceProblemException(500, "The service was unable to build a valid authorization URL");
        }

        return createUserObject(authenticatedWho, uri.toString(), status);
    }

    public List<AuthorizationAttribute> groupAttributes(ObjectDataRequest objectDataRequest) {
        return Lists.newArrayList(new AuthorizationAttribute("member", "Member"));
    }

    public List<AuthorizationAttribute> userAttributes(ObjectDataRequest objectDataRequest) {
        return Lists.newArrayList(new AuthorizationAttribute("user", "User"));
    }

    public List<AuthorizationGroup> groups(ObjectDataRequest objectDataRequest, ApplicationConfiguration configuration) {
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
        return groups
                .map(group -> new AuthorizationGroup(group.getId(), group.getName(), group.getDescription()))
                .collect(Collectors.toList());
    }

    public List<AuthorizationUser> users(ObjectDataRequest objectDataRequest, ApplicationConfiguration configuration) {
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
        return users
                .map(user -> new AuthorizationUser(user.getId(), user.getName().getFullName()))
                .collect(Collectors.toList());
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
            Userinfoplus userInfo;
            try {
                userInfo = getCurrentUser(jsonFactory.fromString(authenticatedWho.getToken(), GoogleTokenResponse.class));
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

    private Userinfoplus getCurrentUser(TokenResponse tokenResponse) {
        GoogleCredential credential = new GoogleCredential()
                .setFromTokenResponse(tokenResponse);

        Oauth2 oauth2 = new Oauth2.Builder(httpTransport, jsonFactory, credential)
                .setApplicationName("Boomi Flow")
                .build();

        try {
            return oauth2.userinfo()
                    .get()
                    .execute();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String getAuthorizationStatus(ApplicationConfiguration configuration, AuthenticatedWho user, Authorization authorization) {
        Directory directory = createDirectory(configuration);

        switch (authorization.getGlobalAuthenticationType()) {
            case Public:
                return "200";
            case AllUsers:
                return isExistingUserAuthorized(user)
                        ? "200"
                        : "401";
            case Specified:
                boolean isAuthorized = isExistingUserAuthorized(user);

                if (!isAuthorized) {
                    // If we're not authorized, we can return early as we don't need to check users or groups
                    return "401";
                }

                // If we're given some groups, check if the user is a member of any of them
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
                        isAuthorized = authorization.getGroups()
                                .stream()
                                .anyMatch(m -> m.getAuthenticationId().equals(group.getId()));
                    }
                }

                // If the user is a member of one or more of the groups, they're good to be authorized
                if (isAuthorized) {
                    return "200";
                }

                // If we're given some users, check if the current user is one of them
                if (CollectionUtils.isNotEmpty(authorization.getUsers())) {
                    isAuthorized = authorization.getUsers()
                            .stream()
                            .anyMatch(m -> m.getAuthenticationId().equals(user.getUserId()));
                }

                // If the current user is one of the given users, they're good to be authorized
                if (isAuthorized) {
                    return "200";
                }

                // Otherwise they're not authorized
                return "401";
            default:
                LOGGER.warn("The authentication type {} is not supported", authorization.getGlobalAuthenticationType());

                return "401";
        }
    }

    private boolean isExistingUserAuthorized(AuthenticatedWho user) {
        if (user.getUserId().equalsIgnoreCase("PUBLIC_USER")) {
            return false;
        }

        GoogleCredential credential;
        try {
            credential = new GoogleCredential()
                    .setFromTokenResponse(jsonFactory.fromString(user.getToken(), GoogleTokenResponse.class));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Check if our current token has expired
        return credential.getExpiresInSeconds() > 0;
    }
}
