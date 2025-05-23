/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
package com.ibm.engine.model.factory;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.TagSize;
import java.util.Optional;
import javax.annotation.Nonnull;

public class TagSizeFactory<T> extends SizeFactory<T> implements IValueFactory<T> {
    public TagSizeFactory() {
        super();
    }

    public TagSizeFactory(@Nonnull Size.UnitType interpretAsUnitType) {
        super(interpretAsUnitType);
    }

    @Nonnull
    @Override
    public Optional<IValue<T>> apply(@Nonnull ResolvedValue<Object, T> objectTResolvedValue) {
        return super.apply(
                objectTResolvedValue,
                (value, tree) -> new TagSize<>(value, Size.UnitType.BIT, tree));
    }
}
