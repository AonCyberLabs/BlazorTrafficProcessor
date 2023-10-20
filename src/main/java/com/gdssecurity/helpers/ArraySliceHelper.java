/**
 * Copyright 2023 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gdssecurity.helpers;

/**
 * Helper class for slicing arrays
 * Used primarily for getting slices of HTTP request/response bodies
 */
public class ArraySliceHelper {
    /**
     * Function to slice a byte array, given the start and end index
     * @param array - the array to slice
     * @param start - the index to start the slice
     * @param end - the index to end the slice
     * @return slicedArray - a new byte array containing the specified slice from the original array
     */
    public static byte[] getArraySlice(byte[] array, int start, int end) {
        if (start >= end) {
            throw new IllegalArgumentException("Start index for array slice must be < end index.");
        }

        if (start < 0 || end > array.length) {
            throw new IllegalArgumentException("Invalid indices for array slice: start=" + start + ", end=" + end);
        }

        byte[] slicedArray = new byte[end - start];
        for (int i = 0; i < slicedArray.length; i++) {
            slicedArray[i] = array[start + i];
        }
        return slicedArray;
    }
}
