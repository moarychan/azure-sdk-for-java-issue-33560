package com.example.extend;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public interface OAuth2UserGrantedAuthoritiesConverter {

    Collection<GrantedAuthority> convert(OidcIdToken idToken);
    Collection<GrantedAuthority> convert(OAuth2AccessToken accessToken);
    Collection<GrantedAuthority> convert(Set<String> allowedGroupIdOrNames);

    default Collection<GrantedAuthority> convert(OidcIdToken idToken,
                                                 OAuth2AccessToken accessToken,
                                                 Set<String> allowedGroupIdOrNames) {
        final Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
        grantedAuthorities.addAll(convert(idToken));
        grantedAuthorities.addAll(convert(accessToken));
        grantedAuthorities.addAll(convert(allowedGroupIdOrNames));
        return grantedAuthorities;
    }
}
