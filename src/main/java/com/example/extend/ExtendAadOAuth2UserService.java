package com.example.extend;

import com.azure.spring.cloud.autoconfigure.implementation.aad.configuration.properties.AadAuthenticationProperties;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.AadOAuth2UserService;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.constants.AadJwtClaimNames;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.constants.AuthorityPrefix;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.graph.GraphClient;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.graph.GroupInformation;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;


public class ExtendAadOAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AadOAuth2UserService.class);

    private final OAuth2UserGrantedAuthoritiesConverter oAuth2UserGrantedAuthoritiesConverter;

    private final List<String> allowedGroupNames;
    private final Set<String> allowedGroupIds;
    private final GraphClient graphClient;
    private static final String DEFAULT_OIDC_USER = "defaultOidcUser";

    public ExtendAadOAuth2UserService(AadAuthenticationProperties properties,
                                      RestTemplateBuilder restTemplateBuilder) {
        this(properties, new GraphClient(properties, restTemplateBuilder), new DefaultOAuth2UserGrantedAuthoritiesConverter());
    }

    public ExtendAadOAuth2UserService(AadAuthenticationProperties properties,
                                      GraphClient graphClient,
                                      OAuth2UserGrantedAuthoritiesConverter oAuth2UserGrantedAuthoritiesConverter) {
        allowedGroupNames = Optional.ofNullable(properties)
                                    .map(AadAuthenticationProperties::getUserGroup)
                                    .map(AadAuthenticationProperties.UserGroupProperties::getAllowedGroupNames)
                                    .orElseGet(Collections::emptyList);
        allowedGroupIds = Optional.ofNullable(properties)
                                  .map(AadAuthenticationProperties::getUserGroup)
                                  .map(AadAuthenticationProperties.UserGroupProperties::getAllowedGroupIds)
                                  .orElseGet(Collections::emptySet);
        this.graphClient = graphClient;
        this.oAuth2UserGrantedAuthoritiesConverter = oAuth2UserGrantedAuthoritiesConverter;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        Assert.notNull(userRequest, "userRequest cannot be null");

        ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        HttpSession session = attr.getRequest().getSession(true);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            LOGGER.debug("User {}'s authorities saved from session: {}.", authentication.getName(), authentication.getAuthorities());
            return (DefaultOidcUser) session.getAttribute(DEFAULT_OIDC_USER);
        }

        DefaultOidcUser defaultOidcUser = getUser(userRequest);
        session.setAttribute(DEFAULT_OIDC_USER, defaultOidcUser);
        return defaultOidcUser;
    }

    DefaultOidcUser getUser(OidcUserRequest userRequest) {
        Set<String> existingGroupIdOrNames = extractGroupIdOrNamesFromAccessToken(userRequest.getAccessToken());
        Collection<GrantedAuthority> authorities = this.oAuth2UserGrantedAuthoritiesConverter.convert(
            userRequest.getIdToken(), userRequest.getAccessToken(), existingGroupIdOrNames);
        if (authorities.isEmpty()) {
            authorities.add(new SimpleGrantedAuthority(AuthorityPrefix.ROLE + "USER"));
        }
        String nameAttributeKey = getNameAttributeKey(userRequest);
        OidcIdToken idToken = userRequest.getIdToken();
        DefaultOidcUser defaultOidcUser = new DefaultOidcUser(authorities, idToken, nameAttributeKey);
        return defaultOidcUser;
    }

    private String getNameAttributeKey(OidcUserRequest userRequest) {
        return Optional.of(userRequest)
                       .map(OAuth2UserRequest::getClientRegistration)
                       .map(ClientRegistration::getProviderDetails)
                       .map(ClientRegistration.ProviderDetails::getUserInfoEndpoint)
                       .map(ClientRegistration.ProviderDetails.UserInfoEndpoint::getUserNameAttributeName)
                       .filter(StringUtils::hasText)
                       .orElse(AadJwtClaimNames.NAME);
    }

    /**
     * Extract group roles from accessToken.
     *
     * @return roles the group roles
     */
    Set<String> extractGroupIdOrNamesFromAccessToken(OAuth2AccessToken accessToken) {
        if (allowedGroupNames.isEmpty() && allowedGroupIds.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> roles = new HashSet<>();
        GroupInformation groupInformation = getGroupInformation(accessToken);
        if (!allowedGroupNames.isEmpty()) {
            Optional.of(groupInformation)
                    .map(GroupInformation::getGroupsNames)
                    .map(Collection::stream)
                    .orElseGet(Stream::empty)
                    .filter(allowedGroupNames::contains)
                    .forEach(roles::add);
        }
        if (!allowedGroupIds.isEmpty()) {
            Optional.of(groupInformation)
                    .map(GroupInformation::getGroupsIds)
                    .map(Collection::stream)
                    .orElseGet(Stream::empty)
                    .filter(this::isAllowedGroupId)
                    .forEach(roles::add);
        }
        return roles;
    }

    private boolean isAllowedGroupId(String groupId) {
        if (allowedGroupIds.size() == 1 && allowedGroupIds.contains("all")) {
            return true;
        }
        return allowedGroupIds.contains(groupId);
    }

    private GroupInformation getGroupInformation(OAuth2AccessToken accessToken) {
        return Optional.of(accessToken)
                       .map(AbstractOAuth2Token::getTokenValue)
                       .map(graphClient::getGroupInformation)
                       .orElseGet(GroupInformation::new);
    }
}
