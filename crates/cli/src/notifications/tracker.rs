use std::collections::BTreeMap;

use super::protocol::{Message, Pane, Status};

#[derive(Debug, PartialEq, Eq)]
pub struct Notice {
    pub title: String,
    pub body: String,
}

#[derive(Default)]
pub struct Tracker {
    panes: BTreeMap<String, Pane>,
    initialized: bool,
}

impl Tracker {
    pub fn apply(&mut self, message: Message) -> Vec<Notice> {
        match message {
            Message::Snapshot { panes } => {
                let mut notices = Vec::new();
                let ids: std::collections::BTreeSet<_> =
                    panes.iter().map(|p| p.pane_id.clone()).collect();
                self.panes.retain(|id, _| ids.contains(id));
                for pane in panes {
                    if let Some(notice) = self.update(pane) {
                        notices.push(notice);
                    }
                }
                self.initialized = true;
                notices
            }
            Message::State { pane }
                if self.initialized && self.panes.contains_key(&pane.pane_id) =>
            {
                self.update(pane).into_iter().collect()
            }
            Message::State { .. } | Message::Heartbeat => Vec::new(),
        }
    }

    fn update(&mut self, mut pane: Pane) -> Option<Notice> {
        let previous = self.panes.get(&pane.pane_id);
        // Status events omit terminal_id. Snapshots identify replaced occupants.
        if pane.terminal_id.is_none() {
            pane.terminal_id = previous.and_then(|p| p.terminal_id.clone());
        }
        let previous = self.panes.insert(pane.pane_id.clone(), pane.clone())?;
        if !self.initialized
            || pane.terminal_id != previous.terminal_id
            || pane.agent != previous.agent
        {
            return None;
        }
        let agent = pane.agent.as_deref().filter(|s| !s.is_empty())?;
        let event = match (previous.agent_status, pane.agent_status) {
            (Status::Working | Status::Blocked, Status::Idle | Status::Done) => "finished",
            (Status::Working | Status::Idle | Status::Done, Status::Blocked) => "needs attention",
            _ => return None,
        };
        Some(Notice {
            title: format!("{} {event}", text(agent, 80)),
            body: format!(
                "{} · {}{}",
                text(&pane.workspace_id, 80),
                text(&pane.pane_id, 80),
                pane.title
                    .as_deref()
                    .map(|t| format!(" · {}", text(t, 160)))
                    .unwrap_or_default()
            ),
        })
    }
}

// Notification content is untrusted display text, never executable input.
pub fn text(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pane(status: Status) -> Pane {
        Pane {
            pane_id: "w1:p1".into(),
            workspace_id: "w1".into(),
            terminal_id: Some("term_1".into()),
            agent_status: status,
            agent: Some("pi".into()),
            title: None,
        }
    }
    fn event(tracker: &mut Tracker, status: Status) -> Vec<Notice> {
        tracker.apply(Message::State { pane: pane(status) })
    }
    #[test]
    fn live_completion_attention_and_seen_transitions() {
        let mut tracker = Tracker::default();
        assert!(
            tracker
                .apply(Message::Snapshot {
                    panes: vec![pane(Status::Idle)]
                })
                .is_empty()
        );
        assert!(event(&mut tracker, Status::Working).is_empty());
        assert_eq!(
            event(&mut tracker, Status::Blocked)[0].title,
            "pi needs attention"
        );
        assert!(event(&mut tracker, Status::Blocked).is_empty());
        assert_eq!(event(&mut tracker, Status::Done)[0].title, "pi finished");
        assert!(event(&mut tracker, Status::Idle).is_empty());
        event(&mut tracker, Status::Working);
        assert_eq!(event(&mut tracker, Status::Idle).len(), 1);
    }
    #[test]
    fn reconnect_new_panes_replacements_and_unknown_states_are_not_history() {
        for status in [Status::Done, Status::Blocked, Status::Unknown] {
            let mut tracker = Tracker::default();
            assert!(event(&mut tracker, status).is_empty());
            assert!(
                tracker
                    .apply(Message::Snapshot {
                        panes: vec![pane(status)]
                    })
                    .is_empty()
            );
            assert!(event(&mut tracker, status).is_empty());
        }
        let mut tracker = Tracker::default();
        tracker.apply(Message::Snapshot {
            panes: vec![pane(Status::Working)],
        });
        let mut replacement = pane(Status::Done);
        replacement.terminal_id = Some("term_2".into());
        assert!(
            tracker
                .apply(Message::Snapshot {
                    panes: vec![replacement]
                })
                .is_empty()
        );
        tracker.apply(Message::Snapshot { panes: vec![] });
        assert!(event(&mut tracker, Status::Done).is_empty());
    }
    #[test]
    fn presentation_changes_do_not_notify_and_controls_are_removed() {
        let mut tracker = Tracker::default();
        tracker.apply(Message::Snapshot {
            panes: vec![pane(Status::Idle)],
        });
        let mut p = pane(Status::Idle);
        p.title = Some("updated title".into());
        assert!(tracker.apply(Message::State { pane: p }).is_empty());
        assert_eq!(text("hello\n\x1b\tworld", 7), "hellowo");
    }
}
