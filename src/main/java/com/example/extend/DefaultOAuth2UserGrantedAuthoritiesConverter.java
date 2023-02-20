package com.example.extend;

import com.azure.spring.cloud.autoconfigure.implementation.aad.security.constants.AadJwtClaimNames;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.constants.AuthorityPrefix;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

public class DefaultOAuth2UserGrantedAuthoritiesConverter implements OAuth2UserGrantedAuthoritiesConverter {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2UserGrantedAuthoritiesConverter.class);

    private final Map<String, String> idTokenClaimToAuthorityPrefixMap = new HashMap<>();
    private final Map<String, String> accessTokenClaimToAuthorityPrefixMap = new HashMap<>();
    private final String groupToAuthorityPrefix;

    public DefaultOAuth2UserGrantedAuthoritiesConverter() {
        this(AuthorityPrefix.ROLE);
    }

    public DefaultOAuth2UserGrantedAuthoritiesConverter(String groupToAuthorityPrefix) {
        this(groupToAuthorityPrefix, defaultIdTokenClaimAuthorityMap(), defaultAccessTokenClaimAuthorityMap());
    }

    public DefaultOAuth2UserGrantedAuthoritiesConverter(String groupToAuthorityPrefix,
                                                        Map<String, String> idTokenClaimToAuthorityPrefixMap,
                                                        Map<String, String> accessTokenClaimToAuthorityPrefixMap) {

        Assert.isTrue(StringUtils.hasText(groupToAuthorityPrefix), "groupToAuthorityPrefix can not be null.");
        Assert.isTrue(!CollectionUtils.isEmpty(idTokenClaimToAuthorityPrefixMap), "idTokenClaimToAuthorityPrefixMap can not be null.");
        Assert.isTrue(!CollectionUtils.isEmpty(accessTokenClaimToAuthorityPrefixMap), "accessTokenClaimToAuthorityPrefixMap can not be null.");
        this.groupToAuthorityPrefix = groupToAuthorityPrefix;
        this.idTokenClaimToAuthorityPrefixMap.putAll(idTokenClaimToAuthorityPrefixMap);
        this.accessTokenClaimToAuthorityPrefixMap.putAll(accessTokenClaimToAuthorityPrefixMap);
    }

    @Override
    public Collection<GrantedAuthority> convert(OidcIdToken idToken) {
        final Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
        idTokenClaimToAuthorityPrefixMap.forEach((authoritiesClaimName, authorityPrefix) ->
            Optional.of(authoritiesClaimName)
                    .map(idToken::getClaim)
                    .map(this::getClaimValueAsCollection)
                    .map(Collection::stream)
                    .orElseGet(Stream::empty)
                    .map(authority -> authorityPrefix + authority)
                    .map(SimpleGrantedAuthority::new)
                    .forEach(grantedAuthorities::add)
        );
        return grantedAuthorities;
    }

    @Override
    public Collection<GrantedAuthority> convert(OAuth2AccessToken accessToken) {
        Set<String> scopes = accessToken.getScopes();
        if (CollectionUtils.isEmpty(scopes) || !accessTokenClaimToAuthorityPrefixMap.containsKey(AadJwtClaimNames.SCP)) {
            return Collections.emptySet();
        }

        final Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
//        String scopeAuthorityPrefix = accessTokenClaimToAuthorityPrefixMap.get(AadJwtClaimNames.SCP);
//        scopes.stream()
//              .map(authority -> scopeAuthorityPrefix + authority)
//              .map(SimpleGrantedAuthority::new)
//              .forEach(grantedAuthorities::add);
        return grantedAuthorities;
    }

    @Override
    public Collection<GrantedAuthority> convert(Set<String> allowedGroupIdOrNames) {
        return getGroupGrantedAuthorities(CollectionUtils.isEmpty(allowedGroupIdOrNames) ? Stream.empty() : allowedGroupIdOrNames.stream());
    }

    private Set<GrantedAuthority> getGroupGrantedAuthorities(Stream<String> groupIdOrNames) {
        final Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
        groupIdOrNames.map(authority -> groupToAuthorityPrefix + authority)
                      .map(SimpleGrantedAuthority::new)
                      .forEach(grantedAuthorities::add);
        return grantedAuthorities;
    }

    private static Map<String, String> defaultAccessTokenClaimAuthorityMap() {
        Map<String, String> accessTokenClaimAuthorityMap = new HashMap<>();
        accessTokenClaimAuthorityMap.put(AadJwtClaimNames.SCP, AuthorityPrefix.SCOPE);
        return accessTokenClaimAuthorityMap;
    }

    private static Map<String, String> defaultIdTokenClaimAuthorityMap() {
        Map<String, String> idTokenClaimAuthorityMap = new HashMap<>();
        idTokenClaimAuthorityMap.put(AadJwtClaimNames.ROLES, AuthorityPrefix.APP_ROLE);
        return idTokenClaimAuthorityMap;
    }

    private Collection<?> getClaimValueAsCollection(Object claimValue) {
        if (claimValue instanceof String) {
            return Arrays.asList(((String) claimValue).split(" "));
        } else if (claimValue instanceof Collection) {
            return (Collection<?>) claimValue;
        } else {
            return Collections.emptyList();
        }
    }
}