/*
 * Copyright 2013-2015 the original author or authors.
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

package org.cloudfoundry.client.spring.util;

import org.cloudfoundry.client.RequestValidationException;
import org.cloudfoundry.client.Validatable;
import org.cloudfoundry.client.ValidationResult;
import org.cloudfoundry.client.spring.v2.CloudFoundryExceptionBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriComponentsBuilder;
import rx.Observable;
import rx.subjects.BehaviorSubject;

import java.net.URI;
import java.util.function.Consumer;
import java.util.function.Supplier;

public abstract class AbstractSpringOperations {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final RestOperations restOperations;

    private final URI root;

    protected AbstractSpringOperations(RestOperations restOperations, URI root) {
        this.restOperations = restOperations;
        this.root = root;
    }

    protected final <T> Observable<T> get(Validatable request, Class<T> responseType,
                                          Consumer<UriComponentsBuilder> uriBuilder) {
        return exchange(request, () -> {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUri(this.root);
            uriBuilder.accept(builder);
            URI uri = builder.build().toUri();

            this.logger.debug("GET {}", uri);
            return this.restOperations.getForObject(uri, responseType);
        });
    }

    protected final <T> Observable<T> delete(Validatable request, T response,
                                             Consumer<UriComponentsBuilder> uriBuilder) {
        return exchange(request, () -> {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUri(this.root);
            uriBuilder.accept(builder);
            URI uri = builder.build().toUri();

            this.logger.debug("DELETE {}", uri);
            this.restOperations.delete(uri);
            return response;
        });
    }

    protected final <T> Observable<T> post(Validatable request, Class<T> responseType,
                                           Consumer<UriComponentsBuilder> uriBuilder) {
        return exchange(request, () -> {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUri(this.root);
            uriBuilder.accept(builder);
            URI uri = builder.build().toUri();

            this.logger.debug("POST {}", uri);
            return this.restOperations.postForObject(uri, request, responseType);
        });
    }

    private <T> Observable<T> exchange(Validatable request, Supplier<T> exchange) {
        return BehaviorSubject.create(subscriber -> {
            if (request != null) {
                ValidationResult validationResult = request.isValid();
                if (validationResult.getStatus() == ValidationResult.Status.INVALID) {
                    subscriber.onError(new RequestValidationException(validationResult));
                    return;
                }
            }

            try {
                subscriber.onNext(exchange.get());
                subscriber.onCompleted();
            } catch (HttpStatusCodeException e) {
                subscriber.onError(CloudFoundryExceptionBuilder.build(e));
            }
        });
    }

}
