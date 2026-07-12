# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Bug Fixes

- **Fix panic: send on closed channel in EnJob.processTask** (2026-03-28)
  - **Issue**: `panic: send on closed channel` occurred at `runner/bean.go:134` in `AddTask` function
  - **Root Cause**: In `EnJob.processTask` (`runner/enscan.go:159-176`), `wg.Done()` was called **before** `AddTask()`, causing a race condition:
    - When the last task's `wg.Done()` executes, `wg.Wait()` in `getInfoById` returns
    - `getInfoById` then calls `closeCH()` to close `taskCh`
    - But `AddTask()` is still trying to send to the now-closed channel → panic
  - **Fix**: Move `wg.Done()` to the end of `processTask`, after all `AddTask()` calls complete
  - **Files Changed**: `runner/enscan.go`
  - **RCA Analysis**: Huawei 5-Why methodology identified the timing sequence bug