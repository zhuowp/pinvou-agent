//! ACP 回合静默看门狗的可单测部分。
//!
//! 宿主只用 `session/prompt` 的响应判定回合结束；一旦 Agent 不再回答，
//! 回合会永久停在 `running`（界面「处理中」），只有重启应用时的孤儿回合
//! 收口能救回来。上游 `claude-agent-acp` 在「后台任务通知自启回合、宿主
//! prompt 被 `absorbed_mid_turn` 吸收」的情况下确实会漏掉这条响应
//! （agentclientprotocol/claude-agent-acp#896/#1027/#1039/#1114）。
//!
//! 本模块只提供判定：活动时钟、静默分级、回合认领与 stderr 提示筛选；
//! 实际动作（提示、请求取消、本地收口）由调用方执行，二者都可单测。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

/// 看门狗巡检间隔。
pub(super) const STALL_TICK: Duration = Duration::from_secs(15);
/// 静默多久先提示用户。Agent 长时间思考不产生事件，只有超过这个量级才值得打扰。
pub(super) const STALL_NOTICE_AFTER: Duration = Duration::from_secs(180);
/// 静默多久开始兜底收口：先请求取消，宽限期后仍无响应则本地收口。
pub(super) const STALL_CANCEL_AFTER: Duration = Duration::from_secs(900);
/// 请求取消后等待 Agent 自行收口的宽限（上游 cancel floor 实测约 30 秒）。
pub(super) const CANCEL_SETTLE_GRACE: Duration = Duration::from_secs(60);
/// 适配器 stderr 提示的最小间隔：同一阵发的多行只提示一次。
pub(super) const STDERR_NOTICE_MIN_INTERVAL: Duration = Duration::from_secs(30);
/// 提示给用户的 stderr 行长度上限（原文截断，不改写）。
pub(super) const STDERR_NOTICE_MAX_CHARS: usize = 400;

/// Agent 侧活动时钟（epoch 毫秒）。只记录 Agent 的活动：入站通知、权限/询问
/// 请求、prompt 响应。宿主自己发出的事件不计入，否则看门狗会被自己的提示刷新。
pub(super) type ActivityClock = Arc<AtomicU64>;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn new_activity_clock() -> ActivityClock {
    Arc::new(AtomicU64::new(now_millis()))
}

pub(super) fn mark_activity(clock: &ActivityClock) {
    clock.store(now_millis(), Ordering::Release);
}

/// 距最近一次 Agent 侧活动的时长。
pub(super) fn quiet_for(clock: &ActivityClock) -> Duration {
    Duration::from_millis(now_millis().saturating_sub(clock.load(Ordering::Acquire)))
}

/// 一轮巡检应执行的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StallStep {
    /// 什么都不做（尚未到阈值，或在等 Agent 回应取消）。
    Idle,
    /// 提示用户 Agent 长时间没有动静（每个回合只提示一次）。
    Notice,
    /// 请求取消，给 Agent 最后一次回答的机会。
    Cancel,
    /// 本地收口：Agent 不再回答这个 prompt，宿主不能永远转圈。
    Settle,
}

/// 静默分级判定。`noticed` 是本回合是否已提示过，`cancel_elapsed` 是发起
/// 取消后经过的时间（尚未发起时为 `None`）。
pub(super) fn stall_step(
    quiet: Duration,
    noticed: bool,
    cancel_elapsed: Option<Duration>,
) -> StallStep {
    if quiet >= STALL_CANCEL_AFTER {
        return match cancel_elapsed {
            None => StallStep::Cancel,
            Some(elapsed) if elapsed >= CANCEL_SETTLE_GRACE => StallStep::Settle,
            Some(_) => StallStep::Idle,
        };
    }
    if !noticed && quiet >= STALL_NOTICE_AFTER {
        StallStep::Notice
    } else {
        StallStep::Idle
    }
}

/// 认领当前回合：第一个认领者清空它，后到的调用方不再补发 `turn_completed`。
/// prompt 响应与看门狗本地收口共享这条路径，晚到的一方必须让位。
pub(super) fn claim_current_turn(current: &RwLock<Option<String>>, turn_id: &str) -> bool {
    let mut guard = current.write();
    if guard.as_deref() == Some(turn_id) {
        *guard = None;
        true
    } else {
        false
    }
}

/// 适配器 stderr 里值得提示用户的片段。上游把真正的异常写成自由文本，这里只
/// 认跨版本稳定的几种措辞，避免把正常会话 banner 刷进界面。
pub(super) fn stderr_notice_worthy(line: &str) -> bool {
    const NEEDLES: [&str; 5] = [
        "cancel floor",
        "wedged",
        "never received",
        "panic",
        "unhandled",
    ];
    let lower = line.to_ascii_lowercase();
    NEEDLES.iter().any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock_aged(age: Duration) -> ActivityClock {
        Arc::new(AtomicU64::new(now_millis() - age.as_millis() as u64))
    }

    #[test]
    fn forkguard_quiet_for_tracks_only_agent_activity() {
        let clock = clock_aged(Duration::from_secs(5));
        assert!(quiet_for(&clock) >= Duration::from_secs(5));
        mark_activity(&clock);
        assert!(quiet_for(&clock) < Duration::from_secs(1));
    }

    #[test]
    fn forkguard_stall_step_escalates_notice_cancel_then_settle() {
        let under = STALL_NOTICE_AFTER - Duration::from_secs(1);
        assert_eq!(
            stall_step(under, false, None),
            StallStep::Idle,
            "尚未到达提示阈值前保持安静"
        );
        assert_eq!(
            stall_step(STALL_NOTICE_AFTER, false, None),
            StallStep::Notice,
            "到达提示阈值先提示用户"
        );
        assert_eq!(
            stall_step(STALL_NOTICE_AFTER + Duration::from_secs(30), true, None),
            StallStep::Idle,
            "同一回合只提示一次"
        );
        assert_eq!(
            stall_step(STALL_CANCEL_AFTER, true, None),
            StallStep::Cancel,
            "继续静默则请求取消"
        );
        assert_eq!(
            stall_step(
                STALL_CANCEL_AFTER + Duration::from_secs(1),
                true,
                Some(CANCEL_SETTLE_GRACE - Duration::from_secs(1))
            ),
            StallStep::Idle,
            "取消宽限期内继续等 Agent"
        );
        assert_eq!(
            stall_step(
                STALL_CANCEL_AFTER + Duration::from_secs(1),
                true,
                Some(CANCEL_SETTLE_GRACE)
            ),
            StallStep::Settle,
            "宽限期用尽后本地收口"
        );
    }

    #[test]
    fn forkguard_stall_step_does_not_settle_without_requesting_cancel_first() {
        assert_eq!(
            stall_step(STALL_CANCEL_AFTER * 2, false, None),
            StallStep::Cancel,
            "即使远超阈值，也必须先发取消再收口"
        );
    }

    #[test]
    fn forkguard_turn_claim_is_exclusive_and_id_scoped() {
        let current = RwLock::new(Some("turn-1".to_string()));
        assert!(claim_current_turn(&current, "turn-1"));
        assert!(
            !claim_current_turn(&current, "turn-1"),
            "晚到的收口方不得重复发 turn_completed"
        );
        let other = RwLock::new(Some("turn-2".to_string()));
        assert!(!claim_current_turn(&other, "turn-1"));
        assert_eq!(other.read().as_deref(), Some("turn-2"));
    }

    #[test]
    fn forkguard_stderr_notice_filters_to_real_agent_trouble() {
        // 现场真实捕获：本次事故里适配器唯一的自述。
        assert!(stderr_notice_worthy(
            "Session e6772626-52a8-45c4-8c2e-e89ddfefea99: cancel floor elapsed without the SDK yielding; forcing \"cancelled\". The underlying query may still be wedged — a new session may be required."
        ));
        assert!(stderr_notice_worthy(
            "Internal error: \"response to `session/prompt` never received: oneshot canceled\""
        ));
        assert!(stderr_notice_worthy("PANIC: unwrap failed"));
        // 正常启动 banner 与普通日志不提示用户。
        assert!(!stderr_notice_worthy(
            "[session/query] sessionId=e6772626-52a8-45c4-8c2e-e89ddfefea99 resume=none apiType=native baseUrl=native"
        ));
        assert!(!stderr_notice_worthy(""));
    }
}
