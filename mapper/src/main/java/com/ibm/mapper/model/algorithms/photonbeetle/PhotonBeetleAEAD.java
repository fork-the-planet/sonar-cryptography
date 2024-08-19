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
package com.ibm.mapper.model.algorithms.photonbeetle;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.NonceLength;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public class PhotonBeetleAEAD extends Algorithm implements AuthenticatedEncryption {
    // https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/photon-beetle-spec-round2.pdf

    private static final String NAME = "PHOTON-Beetle-AEAD";

    public PhotonBeetleAEAD(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, AuthenticatedEncryption.class, detectionLocation);
        this.put(new KeyLength(128, detectionLocation));
        this.put(new TagLength(128, detectionLocation));
        this.put(new NonceLength(128, detectionLocation));
    }

    public PhotonBeetleAEAD(int rate, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new BlockSize(rate, detectionLocation));
    }
}