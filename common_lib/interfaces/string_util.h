/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef STRING_UTIL_H
#define STRING_UTIL_H

#include <stdint.h>
#include "uint8buff_utils.h"

#define BYTE_TO_HEX_OPER_LENGTH 2
#define BYTE_TO_BASE64_DIVISOR 3
#define BYTE_TO_BASE64_MULTIPLIER 4
#define DEC 10

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Convert hex string to byte.
 * @param hexStr: hex string
 * @param byte: the converted result, need malloc by caller
 * @param byteLen: the length of byte, must be not shorter than strlen(hexStr) / 2
 * @result success(0), otherwise, failure.
 */
int32_t HexStringToByte(const char *hexStr, uint8_t *byte, uint32_t byteLen);

/*
 * Convert byte to hex string.
 * @param byte: byte to be converted
 * @param byteLen: the length of byte
 * @param hexStr: the converted result, need malloc by caller, and need malloc for '\0'
 * @param hexLen: length of hexStr, must be not shorter than byteLen * 2 + 1, for '\0'
 * @result success(0), otherwise, failure.
 */
int32_t ByteToHexString(const uint8_t *byte, uint32_t byteLen, char *hexStr, uint32_t hexLen);

/*
 * Convert string to int64_t.
 * @param cp: string to be converted
 * @return the converted result.
 */
int64_t StringToInt64(const char *cp);

/*
 * Convert string to upper case.
 * @param oriStr: original string.
 * @param desStr: the converted result. Need free.
 * @return success(0), otherwise, failure.
 */
int32_t ToUpperCase(const char *oriStr, char **desStr);

/*
 * Deep copy string.
 * @param str: original string.
 * @param newStr: the new string. Need free.
 * @return success(0), otherwise, failure.
 */
int32_t DeepCopyString(const char *str, char **newStr);

#ifdef __cplusplus
}
#endif
#endif