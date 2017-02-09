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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

final class TokenUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger("cloudfoundry-client.token");

    private static final ZoneId UTC = ZoneId.of("UTC");

    private TokenUtils() {
    }

    static void logAccessToken(String accessToken) {
        logToken("Access", accessToken);
    }

    static void logRefreshToken(String refreshToken) {
        logToken("Refresh", refreshToken);
    }

    private static void logToken(String type, String token) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("{} Token: {}", type, token);

            parseToken(token)
                .ifPresent(claims -> {
                    LOGGER.debug("{} Token Issued At:  {} UTC", type, toLocalDateTime(claims.getIssuedAt()));
                    LOGGER.debug("{} Token Expires At: {} UTC", type, toLocalDateTime(claims.getExpiration()));
                });
        }
    }

    private static Optional<Claims> parseToken(String token) {
        try {
            String jws = token.substring(0, token.lastIndexOf('.') + 1);
            return Optional.of(Jwts.parser().parseClaimsJwt(jws).getBody());
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static LocalDateTime toLocalDateTime(Date date) {
        return LocalDateTime.from(date.toInstant().atZone(UTC));
    }

}
