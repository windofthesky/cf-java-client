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

package org.cloudfoundry.client.v3.applications;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.Nullable;
import org.immutables.value.Value;

/**
 * The request payload for the Scale Application operation
 */
@Value.Immutable
abstract class _ScaleApplicationRequest {

    /**
     * The application id
     */
    @JsonIgnore
    abstract String getApplicationId();

    /**
     * The disk size
     */
    @JsonProperty("disk_in_mb")
    @Nullable
    abstract Integer getDiskInMb();

    /**
     * The number of instances
     */
    @JsonProperty("instances")
    @Nullable
    abstract Integer getInstances();

    /**
     * The memory size
     */
    @JsonProperty("memory_in_mb")
    @Nullable
    abstract Integer getMemoryInMb();

    /**
     * The type
     */
    @JsonIgnore
    abstract String getType();

}
