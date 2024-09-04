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
package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.ClassicalBitSecurityLevel;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public final class MarsupilamiFourteen extends Algorithm implements MessageDigest {
    // https://eprint.iacr.org/2016/770.pdf

    private static final String NAME = "MarsupilamiFourteen";

    public MarsupilamiFourteen(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, MessageDigest.class, detectionLocation);
        this.put(new ClassicalBitSecurityLevel(256, detectionLocation));
        this.put(new NumberOfIterations(14, detectionLocation));
    }

    public MarsupilamiFourteen(int digestSize, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new DigestSize(digestSize, detectionLocation));
    }
}