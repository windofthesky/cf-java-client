/*
 * Copyright 2013-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.reactor.tokenprovider;

import org.cloudfoundry.reactor.ConnectionContext;
import org.cloudfoundry.reactor.TokenProvider;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import reactor.core.publisher.Mono;

/**
 * An implementation of {@link TokenProvider} that extracts the access token from a {@link SecurityContextHolder}.
 */
public final class SpringSecurityOAuth2TokenProvider implements TokenProvider {

    private static final Mono<String> TOKEN = Mono
        .defer(() -> Mono.justOrEmpty(SecurityContextHolder.getContext().getAuthentication()))
        .otherwiseIfEmpty(Mono.error(new IllegalStateException("Current request is not authenticated")))
        .then(authentication -> Mono.justOrEmpty(authentication.getDetails()))
        .otherwiseIfEmpty(Mono.error(new IllegalStateException("Current request does not expose request details")))
        .cast(OAuth2AuthenticationDetails.class)
        .mapError(ClassCastException.class, t -> new IllegalStateException("Current request is not authenticated with OAuth2"))
        .map(details -> {
            String accessToken = details.getTokenValue();
            TokenUtils.logAccessToken(accessToken);
            return String.format("%s %s", details.getTokenType(), accessToken);
        });

    @Override
    public Mono<String> getToken(ConnectionContext connectionContext) {
        return TOKEN;
    }

}
