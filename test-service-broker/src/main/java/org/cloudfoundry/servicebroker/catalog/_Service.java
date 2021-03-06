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

package org.cloudfoundry.servicebroker.catalog;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.servicebroker.Nullable;
import org.immutables.value.Value;

import java.util.List;

@Value.Immutable
abstract class _Service {

    @JsonProperty("bindable")
    abstract boolean getBindable();

    @JsonProperty("dashboard_client")
    abstract DashboardClient getDashboardClient();

    @JsonProperty("description")
    abstract String getDescription();

    @JsonProperty("id")
    abstract String getId();

    @JsonProperty("max_db_per_node")
    @Nullable
    abstract Integer getMaxDbPerNode();

    @JsonProperty("metadata")
    abstract ServiceMetadata getMetadata();

    @JsonProperty("name")
    abstract String getName();

    @JsonProperty("plan_updateable")
    abstract Boolean getPlanUpdateable();

    @JsonProperty("plans")
    abstract List<Plan> getPlans();

    @JsonProperty("requires")
    abstract List<String> getRequires();

    @JsonProperty("tags")
    abstract List<String> getTags();

}
