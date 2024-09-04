/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2024 IBM
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
package com.ibm.mapper.model.algorithms.cast;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public final class CAST256 extends Algorithm implements BlockCipher {
    // https://en.wikipedia.org/wiki/CAST-256

    private static final String NAME = "CAST-256"; // CAST6

    // "256" refers to the maximum size of the key

    public CAST256(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, BlockCipher.class, detectionLocation);
        this.put(new BlockSize(128, detectionLocation));
    }

    public CAST256(int keyLength, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
    }

    public CAST256(
            int keyLength, @Nonnull Mode mode, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(mode);
    }

    public CAST256(
            int keyLength,
            @Nonnull Mode mode,
            @Nonnull Padding padding,
            @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(mode);
        this.put(padding);
    }

    public CAST256(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull CAST256 cast256) {
        super(cast256, asKind);
    }
}