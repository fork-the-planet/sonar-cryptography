/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.output.cyclondx.builder;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.evidence.Occurrence;

public interface IProtocolComponentBuilder {

    @Nonnull
    IProtocolComponentBuilder name(@Nullable Protocol name);

    @Nonnull
    IProtocolComponentBuilder type(@Nullable Protocol type);

    @Nonnull
    IProtocolComponentBuilder version(@Nullable INode version);

    @Nonnull
    IProtocolComponentBuilder cipherSuites(@Nullable INode cipherSuiteCollection);

    @Nonnull
    IProtocolComponentBuilder occurrences(@Nullable Occurrence... occurrences);

    @Nonnull
    Component build();
}
