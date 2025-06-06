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

#ifndef PAKE_V1_PROTOCOL_TASK_COMMOM_H
#define PAKE_V1_PROTOCOL_TASK_COMMOM_H

#include "pake_base_cur_task.h"
#include "json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitDasPakeV1Params(PakeParams *params, const CJson *in);
void DestroyDasPakeV1Params(PakeParams *params);
int32_t FillPskWithDerivedKeyHex(PakeParams *params);
int32_t LoadPseudonymExtInfoIfNeed(PakeParams *params);
int32_t AddPseudonymIdAndChallenge(PakeParams *params, CJson *payload);
int32_t CheckPseudonymId(PakeParams *params, const CJson *in);
int32_t SaveNextPseudonymIdAndChallenge(PakeParams *params);

#ifdef __cplusplus
}
#endif
#endif