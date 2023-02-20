package com.example.extend;

import com.azure.spring.cloud.autoconfigure.implementation.aad.configuration.properties.AadAuthenticationProperties;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.constants.AadJwtClaimNames;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.constants.AuthorityPrefix;
import com.azure.spring.cloud.autoconfigure.implementation.aad.security.graph.GraphClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.HashMap;
import java.util.Map;

@Configuration(proxyBeanMethods = false)
public class ExtendConfiguration {

//    @Bean
//    @ConditionalOnMissingBean
//    OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService(AadAuthenticationProperties properties,
//                                                                 RestTemplateBuilder restTemplateBuilder) {
//        return new ExtendAadOAuth2UserService(properties, restTemplateBuilder);
//    }

    @Bean
    @ConditionalOnMissingBean
    OAuth2UserService<OidcUserRequest, OidcUser> extendOidcUserService(AadAuthenticationProperties properties,
                                                                 RestTemplateBuilder restTemplateBuilder) {
        Map<String, String> idTokenClaimAuthorityMap = new HashMap<>();
        idTokenClaimAuthorityMap.put(AadJwtClaimNames.ROLES, AuthorityPrefix.APP_ROLE);


        Map<String, String> accessTokenClaimAuthorityMap = new HashMap<>();
        accessTokenClaimAuthorityMap.put(AadJwtClaimNames.SCP, AuthorityPrefix.SCOPE);

        DefaultOAuth2UserGrantedAuthoritiesConverter auth2UserGrantedAuthoritiesConverter =
            new DefaultOAuth2UserGrantedAuthoritiesConverter("GROUP_", idTokenClaimAuthorityMap, accessTokenClaimAuthorityMap);
        return new ExtendAadOAuth2UserService(properties,
            new GraphClient(properties, restTemplateBuilder),
            auth2UserGrantedAuthoritiesConverter);
    }
}
