/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.brooklyn.rest.filter;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.reflect.TypeToken;
import org.apache.brooklyn.api.mgmt.ManagementContext;
import org.apache.brooklyn.config.ConfigKey;
import org.apache.brooklyn.config.StringConfigMap;
import org.apache.brooklyn.core.BrooklynFeatureEnablement;
import org.apache.brooklyn.core.config.ConfigKeys;
import org.apache.cxf.rs.security.cors.CrossOriginResourceSharingFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.ext.Provider;
import java.util.Collections;
import java.util.List;

/**
 * @see BrooklynFeatureEnablement#FEATURE_CORS_CXF_PROPERTY
 */
@Provider
public class CorsImplSupplierFilter extends CrossOriginResourceSharingFilter {
    /**
     * @see CrossOriginResourceSharingFilter#setAllowOrigins(List<String>)
     */
    public static final ConfigKey<List<String>> ALLOWED_ORIGINS = ConfigKeys.newConfigKey(new TypeToken<List<String>>() {},
            BrooklynFeatureEnablement.FEATURE_CORS_CXF_PROPERTY + ".allowedOrigins",
            "List of allowed origins. Access-Control-Allow-Origin header will be returned to client if Origin header in request is matching exactly a value among the list allowed origins. " +
                    "If AllowedOrigins is empty or not specified then all origins are allowed. " +
                    "No wildcard allowed origins are supported.",
            Collections.<String>emptyList());
    
    /**
     * @see CrossOriginResourceSharingFilter#setAllowHeaders(List<String>) 
     */
    public static final ConfigKey<List<String>> ALLOWED_HEADERS = ConfigKeys.newConfigKey(new TypeToken<List<String>>() {},
            BrooklynFeatureEnablement.FEATURE_CORS_CXF_PROPERTY + ".allowedHeaders",
            "List of allowed headers for preflight checks.",
            Collections.<String>emptyList());

    /**
     * @see CrossOriginResourceSharingFilter#setAllowCredentials(boolean)
     */
    public static final ConfigKey<Boolean> ALLOW_CREDENTIALS = ConfigKeys.newBooleanConfigKey(
            BrooklynFeatureEnablement.FEATURE_CORS_CXF_PROPERTY + ".allowCredentials",
            "The value for the Access-Control-Allow-Credentials header. If false, no header is added. If true, the\n" +
                    "     * header is added with the value 'true'. False by default.",
            false);

    /**
     * @see CrossOriginResourceSharingFilter#setExposeHeaders(List<String>) 
     */
    public static final ConfigKey<List<String>> EXPOSED_HEADERS = ConfigKeys.newConfigKey(new TypeToken<List<String>>() {},
            BrooklynFeatureEnablement.FEATURE_CORS_CXF_PROPERTY + ".exposedHeaders",
            "A list of non-simple headers to be exposed via Access-Control-Expose-Headers.",
            Collections.<String>emptyList());

    /**
     * @see CrossOriginResourceSharingFilter#setMaxAge(Integer) 
     */
    public static final ConfigKey<Integer> MAX_AGE = ConfigKeys.newIntegerConfigKey(
            BrooklynFeatureEnablement.FEATURE_CORS_CXF_PROPERTY + ".maxAge",
            "The value for Access-Control-Max-Age.",
            null);

    /**
     * @see CrossOriginResourceSharingFilter#setPreflightErrorStatus(Integer)
     */
    public static final ConfigKey<Integer> PREFLIGHT_FAIL_STATUS = ConfigKeys.newIntegerConfigKey(
            BrooklynFeatureEnablement.FEATURE_CORS_CXF_PROPERTY + ".preflightFailStatus",
            "Preflight error response status, default is 200.",
            200);

    public static final ConfigKey<Boolean> BLOCK_CORS_IF_UNAUTHORIZED = ConfigKeys.newBooleanConfigKey(
            BrooklynFeatureEnablement.FEATURE_CORS_CXF_PROPERTY + ".blockCorsIfUnauthorized",
            "Do not apply CORS if response is going to be with UNAUTHORIZED status.",
            false);

    private static final Logger LOGGER = LoggerFactory.getLogger(CorsImplSupplierFilter.class);

    private static final boolean brooklynFeatureEnabled = BrooklynFeatureEnablement.isEnabled(BrooklynFeatureEnablement.FEATURE_CORS_CXF_PROPERTY);
    static {
        if (brooklynFeatureEnabled) {
            LOGGER.info("CORS brooklyn feature enabled.");
        }
    }
    
    @VisibleForTesting
    public CorsImplSupplierFilter(@Nullable ManagementContext mgmt) {
        Preconditions.checkNotNull(mgmt,"ManagementContext should be suppplied to CORS filter.");
        setFindResourceMethod(false);
        StringConfigMap configMap = mgmt.getConfig();
        setAllowOrigins(configMap.getConfig(ALLOWED_ORIGINS));
        setAllowHeaders(configMap.getConfig(ALLOWED_HEADERS));
        setAllowCredentials(configMap.getConfig(ALLOW_CREDENTIALS));
        setExposeHeaders(configMap.getConfig(EXPOSED_HEADERS));
        setMaxAge(configMap.getConfig(MAX_AGE));
        setPreflightErrorStatus(configMap.getConfig(PREFLIGHT_FAIL_STATUS));
        setBlockCorsIfUnauthorized(configMap.getConfig(BLOCK_CORS_IF_UNAUTHORIZED));
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        if (brooklynFeatureEnabled) {
            super.filter(requestContext);
        }
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        if (brooklynFeatureEnabled) {
            super.filter(requestContext, responseContext);
        }
    }
}
