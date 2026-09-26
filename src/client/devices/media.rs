//! Audio playback controls (Arlo audio doorbells / chimes).

use crate::client::ArloClient;
use crate::error::ArloError;
use serde_json::json;

impl ArloClient {
    /// Plays a specific audio track on the Arlo Baby monitor, or resumes playback if no track is provided.
    pub async fn play_track(
        &self,
        camera_id: &str,
        track_id: Option<&str>,
        position: u32,
    ) -> Result<(), ArloError> {
        let (action, properties) = if let Some(t_id) = track_id {
            (
                "playTrack",
                Some(json!({
                    "trackId": t_id,
                    "position": position
                })),
            )
        } else {
            ("play", None)
        };

        self.notify_custom_resource(camera_id, "audioPlayback/player", action, properties)
            .await
    }

    /// Pauses the currently playing audio track on the Arlo Baby monitor.
    pub async fn pause_track(&self, camera_id: &str) -> Result<(), ArloError> {
        self.notify_custom_resource(camera_id, "audioPlayback/player", "pause", None)
            .await
    }

    /// Skips to the next audio track in the playlist.
    pub async fn next_track(&self, camera_id: &str) -> Result<(), ArloError> {
        self.notify_custom_resource(camera_id, "audioPlayback/player", "nextTrack", None)
            .await
    }

    /// Skips to the previous audio track in the playlist.
    pub async fn previous_track(&self, camera_id: &str) -> Result<(), ArloError> {
        self.notify_custom_resource(camera_id, "audioPlayback/player", "prevTrack", None)
            .await
    }

    /// Sets the speaker volume and mute status for the device.
    pub async fn set_volume(
        &self,
        camera_id: &str,
        mute: bool,
        volume: u8,
    ) -> Result<(), ArloError> {
        self.notify(
            camera_id,
            "set",
            Some(json!({
                "speaker": {
                    "mute": mute,
                    "volume": volume.min(100) // Caps at 100
                }
            })),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::client::devices::test_support::*;
    use crate::client::test_helpers::{authenticated_mocked_client, parse_body_json};
    use std::sync::Arc;

    #[tokio::test]
    async fn set_volume_clamps_to_100() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.set_volume("CAM-1", false, 250).await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        let speaker = &body["properties"]["speaker"];
        assert_eq!(speaker["mute"], false);
        assert_eq!(speaker["volume"], 100);
    }

    #[tokio::test]
    async fn play_track_with_track_id_emits_play_track_action() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client
            .play_track("BABY-1", Some("track-9"), 42)
            .await
            .unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["resource"], "audioPlayback/player");
        assert_eq!(body["action"], "playTrack");
        assert_eq!(body["properties"]["trackId"], "track-9");
        assert_eq!(body["properties"]["position"], 42);
    }

    #[tokio::test]
    async fn play_track_without_track_id_resumes_with_play_action() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.play_track("BABY-1", None, 0).await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["action"], "play");
        // properties is the default empty object
        assert!(body["properties"].as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pause_next_prev_track_emit_correct_actions() {
        for (op, expected) in [
            ("pause", "pause"),
            ("next", "nextTrack"),
            ("prev", "prevTrack"),
        ] {
            let mock = arc_mock();
            mock.queue_post("{}");
            let client = authenticated_mocked_client(Arc::clone(&mock));
            match op {
                "pause" => client.pause_track("BABY-1").await.unwrap(),
                "next" => client.next_track("BABY-1").await.unwrap(),
                "prev" => client.previous_track("BABY-1").await.unwrap(),
                _ => unreachable!(),
            }
            let body = parse_body_json(mock.calls()[1].body.as_ref());
            assert_eq!(body["resource"], "audioPlayback/player");
            assert_eq!(body["action"], expected);
        }
    }
}
