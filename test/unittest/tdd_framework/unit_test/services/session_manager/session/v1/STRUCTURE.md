# V1 Sub-Session Test Directory Structure

## Directory Layout

```
test/mock_inner/services/                      # Reusable mock infrastructure (shared globally)
├── frameworks/module/
│   ├── dev_auth_module_manager_mock.c          # Replaces dev_auth_module_manager.c
│   └── dev_auth_module_manager_mock.h          # SetCreateTaskResult / SetProcessTaskResult
├── legacy/group_auth/group_auth_manager/group_auth_common/
│   ├── group_auth_data_operation_mock.c        # Replaces group_auth_data_operation.c
│   └── group_auth_data_operation_mock.h        # SetGa*Result
├── data_manager/group_data_manager/
│   ├── group_data_manager_mock.c               # Replaces group_data_manager.c + _util.c
│   └── group_data_manager_mock.h               # SetAddGroupResult / SetQueryGroupsResult
└── legacy/group_manager/group_operation/group_operation_common/
    ├── group_operation_common_mock.c           # Replaces group_operation_common.c
    └── group_operation_common_mock.h           # SetCheckGroupExistResult etc.

test/unittest/.../session/v1/
├── compatible_sub_session/                     # Integration test target (real DB + V1 routing)
│   ├── BUILD.gn
│   ├── compatible_sub_session_test.cpp         # dispatcher + helpers (13 cases)
│   ├── compatible_bind_sub_session_test.cpp    # bind create/process/integration (14 cases)
│   ├── compatible_auth_sub_session_test.cpp    # auth create/process/integration (12 cases)
│   └── compatible_sub_session_exception_test.cpp # exception injection (13 cases)
├── compatible_sub_session_mock/                # Pure-mock test target
│   ├── BUILD.gn                                # References mock_inner via absolute paths
│   ├── compatible_bind_sub_session_mock_test.cpp        # 82 cases
│   ├── compatible_auth_sub_session_mock_test.cpp        # 80 cases
│   └── compatible_bind_sub_session_common_mock_test.cpp # 6 cases
├── common/                                     # Shared test helpers
│   ├── BUILD.gn
│   ├── test_helper.h
│   └── test_helper.cpp
└── STRUCTURE.md
```

## Mock Infrastructure Organization

Mock files are organized under `test/mock_inner/services/` mirroring the
source tree layout, consistent with the existing
`test/mock_inner/services/frameworks/os_account_adapter/`.
Other test targets reuse these mocks by adding the corresponding
`include_dirs` and referencing the mock `.c` files via absolute paths in
their `BUILD.gn` `sources`. No local copies are made.

## Two Test Targets

| Target | Characteristics | Use Case |
|--------|-----------------|----------|
| `compatible_sub_session_test` | Real DB + V1 routing + end-to-end exchange | Success paths + integration interaction |
| `compatible_sub_session_mock_test` | 4-layer controllable mock + exception injection | Error / boundary / failure branches |

## Mock Test Strategy

1. **Controllable mocks**: `Set*Result()` APIs control return values to drive each error branch precisely.
2. **Exception injection**: `exception_controller` + `memory_mock` inject the N-th malloc/cJSON failure.
3. **Constructed input**: Build JSON params with missing or invalid fields to cover value-check branches.
4. **sendToPeer injection**: The mock ProcessTask injects sendToPeer on CONTINUE/FINISH to exercise SendBindDataToPeer / OnSessionFinish paths without a real protocol exchange.

## Four Mock Modules

| Module | Source Path | Controllable API |
|--------|-------------|------------------|
| `dev_auth_module_manager_mock` | `frameworks/module/` | SetCreateTaskResult / SetProcessTaskResult / ResetModuleMock |
| `group_auth_data_operation_mock` | `legacy/group_auth/.../group_auth_common/` | SetGaGetLocalDeviceInfoResult / SetGaIsGroupAccessible / ResetGaMock |
| `group_data_manager_mock` | `data_manager/group_data_manager/` | SetAddGroupResult / SetAddTrustedDeviceResult / SetQueryGroupsResult / ResetDbMock |
| `group_operation_common_mock` | `legacy/group_manager/.../group_operation_common/` | SetCheckGroupExistResult / SetProcessKeyPairResult / ResetGroupOpMock |
