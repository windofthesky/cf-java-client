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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import java.time.Duration;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class SpringSecurityOAuth2TokenProviderTest {

    private final Authentication authentication = mock(Authentication.class);

    private final OAuth2AuthenticationDetails oAuth2AuthenticationDetails = mock(OAuth2AuthenticationDetails.class);

    private final SecurityContext securityContext = mock(SecurityContext.class);

    private final SpringSecurityOAuth2TokenProvider tokenProvider = new SpringSecurityOAuth2TokenProvider();

    @Test
    public void noDetails() {
        when(this.securityContext.getAuthentication()).thenReturn(this.authentication);

        this.tokenProvider
            .getToken(null)
            .as(StepVerifier::create)
            .expectErrorMessage("Current request does not expose request details")
            .verify(Duration.ofSeconds(1));
    }

    @Test
    public void noOAuth2Details() {
        when(this.securityContext.getAuthentication()).thenReturn(this.authentication);
        when(this.authentication.getDetails()).thenReturn(new Object());

        this.tokenProvider
            .getToken(null)
            .as(StepVerifier::create)
            .expectErrorMessage("Current request is not authenticated with OAuth2")
            .verify(Duration.ofSeconds(1));
    }

    @Test
    public void notAuthenticated() {

        this.tokenProvider
            .getToken(null)
            .as(StepVerifier::create)
            .expectErrorMessage("Current request is not authenticated")
            .verify(Duration.ofSeconds(1));
    }

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.setContext(this.securityContext);
    }

    @Test
    public void success() {
        when(this.securityContext.getAuthentication()).thenReturn(this.authentication);
        when(this.authentication.getDetails()).thenReturn(this.oAuth2AuthenticationDetails);
        when(this.oAuth2AuthenticationDetails.getTokenType()).thenReturn("test-token-type");
        when(this.oAuth2AuthenticationDetails.getTokenValue()).thenReturn("test-token-value");

        this.tokenProvider
            .getToken(null)
            .as(StepVerifier::create)
            .expectNext("test-token-type test-token-value")
            .expectComplete()
            .verify(Duration.ofSeconds(1));
    }

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

}
