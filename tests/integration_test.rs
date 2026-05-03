//! End-to-end integration tests for UDP broadcast relay using Docker.
//!
//! These tests use testcontainers to spin up a privileged Docker container
//! with network namespaces for testing broadcast relay functionality.
//!
//! # Test Architecture
//!
//! Each test creates:
//! - A privileged Docker container with network tools
//! - Two network namespaces (ns_sender, ns_receiver) inside the container
//! - veth pairs connecting namespaces to the default namespace
//! - The relay binary runs in the default namespace
//!
//! # Running Tests
//!
//! ```bash
//! cargo build --release
//! cargo test --test integration_test
//! ```

use std::{path::Path, time::Duration};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, core::ExecCommand, runners::AsyncRunner,
};

const TEST_PORT: u16 = 9999;

/// Helper struct to manage the test container
struct TestContainer {
    container: ContainerAsync<GenericImage>,
}

impl TestContainer {
    /// Build the Docker image and start a privileged container
    async fn start(binary_file_dir: &Path) -> Self {
        // Build the test Docker image first
        let build_output = std::process::Command::new("docker")
            .args([
                "build",
                "--build-context",
                &format!(
                    "bin-file-dir={}",
                    binary_file_dir.as_os_str().to_string_lossy()
                ),
                "-t",
                "udp-relay-test:latest",
                "-f",
                "tests/docker/Dockerfile",
                ".",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Failed to run docker build");

        if !build_output.status.success() {
            panic!(
                "Docker build failed:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&build_output.stdout),
                String::from_utf8_lossy(&build_output.stderr)
            );
        }

        // Start the container in privileged mode (needed for network namespaces)
        let container = GenericImage::new("udp-relay-test", "latest")
            .with_privileged(true)
            .start()
            .await
            .expect("Failed to start test container");

        Self { container }
    }

    /// Setup network namespaces inside the container
    async fn setup_namespaces(&self) {
        let mut result = self
            .container
            .exec(ExecCommand::new(["setup_namespaces.sh"]))
            .await
            .expect("Failed to setup namespaces");

        // Wait for the command to complete
        // let output = result.stdout_to_vec().await.unwrap();
        let stderr = result.stderr_to_vec().await.unwrap();

        if !stderr.is_empty() {
            let stderr_str = String::from_utf8_lossy(&stderr);
            if stderr_str.contains("error") || stderr_str.contains("Error") {
                panic!("Namespace setup failed: {}", stderr_str);
            }
        }
    }

    /// Start the relay process in the container's default namespace
    async fn start_relay(&self, id: u8, port: u16, interfaces: &[&str]) {
        let ifaces = interfaces.join(" ");
        let cmd = format!(
            "udp-bcast-relay-rs -v {} {} {} > /tmp/relay.log 2>&1 &",
            id, port, ifaces
        );

        self.container
            .exec(ExecCommand::new(["bash", "-c", &cmd]))
            .await
            .expect("Failed to start relay");

        // Give relay time to start
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    /// Start a UDP listener in the specified namespace
    async fn start_listener(&self, namespace: &str, port: u16, output_file: &str) {
        // Using socat for UDP listening
        let cmd = format!(
            "ip netns exec {} sh -c 'socat -u UDP4-RECV:{},broadcast OPEN:{},create,append 2>&1 &'",
            namespace, port, output_file
        );
        self.container
            .exec(ExecCommand::new(["bash", "-c", &cmd]))
            .await
            .expect("Failed to start listener");

        // Give listener time to start
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    /// Send a UDP broadcast from the specified namespace
    async fn send_broadcast(
        &self,
        namespace: &str,
        broadcast_addr: &str,
        port: u16,
        message: &str,
    ) {
        let cmd = format!(
            "ip netns exec {} sh -c 'echo -n \"{}\" | socat - UDP4-DATAGRAM:{}:{},broadcast'",
            namespace, message, broadcast_addr, port
        );

        self.container
            .exec(ExecCommand::new(["bash", "-c", &cmd]))
            .await
            .expect("Failed to send broadcast");

        // Give time for the message to be relayed
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    /// Read the contents of a file in the container
    async fn read_file(&self, path: &str) -> String {
        let mut result = self
            .container
            .exec(ExecCommand::new(["cat", path]))
            .await
            .expect("Failed to read file");

        let output = result.stdout_to_vec().await.unwrap();
        String::from_utf8_lossy(&output).to_string()
    }

    /// Run a command and get its output
    async fn exec(&self, cmd: &str) -> String {
        let mut result = self
            .container
            .exec(ExecCommand::new(["bash", "-c", cmd]))
            .await
            .expect("Failed to execute command");

        let output = result.stdout_to_vec().await.unwrap();
        String::from_utf8_lossy(&output).to_string()
    }
}

/// Helper to setup the test environment
async fn setup_test_environment() -> TestContainer {
    let binary = assert_cmd::cargo::cargo_bin!();
    let bin_dir = binary
        .parent()
        .expect("Could not determine binary directory");
    let container = TestContainer::start(bin_dir).await;
    container.setup_namespaces().await;
    container
}

/// Test that UDP broadcasts are relayed from one network to another
#[tokio::test]
async fn test_basic_broadcast_relay() {
    let container = setup_test_environment().await;

    // Start listener in ns_receiver
    container
        .start_listener("ns_receiver", TEST_PORT, "/tmp/received.txt")
        .await;

    container
        .start_relay(1, TEST_PORT, &["veth1b", "veth2b"])
        .await;

    // Send broadcast from ns_sender
    let test_message = "RELAY_TEST_BASIC_12345";
    container
        .send_broadcast("ns_sender", "10.0.1.255", TEST_PORT, test_message)
        .await;

    let received = container.read_file("/tmp/received.txt").await;

    assert_eq!(
        received, test_message,
        "Expected to receive '{}' but got '{}'",
        test_message, received
    );
}

/// Test that relay works in both directions
#[tokio::test]
async fn test_bidirectional_relay() {
    let container = setup_test_environment().await;

    container
        .start_relay(1, TEST_PORT, &["veth1b", "veth2b"])
        .await;

    // Test direction 1: ns_sender -> ns_receiver
    container
        .start_listener("ns_receiver", TEST_PORT, "/tmp/received1.txt")
        .await;

    let msg1 = "DIRECTION_1_TEST";
    container
        .send_broadcast("ns_sender", "10.0.1.255", TEST_PORT, msg1)
        .await;

    let received1 = container.read_file("/tmp/received1.txt").await;
    assert_eq!(
        received1, msg1,
        "Direction 1 failed: expected '{}', got '{}'",
        msg1, received1
    );

    // Test direction 2: ns_receiver -> ns_sender
    container
        .start_listener("ns_sender", TEST_PORT, "/tmp/received2.txt")
        .await;

    let msg2 = "DIRECTION_2_TEST";
    container
        .send_broadcast("ns_receiver", "10.0.2.255", TEST_PORT, msg2)
        .await;

    let received2 = container.read_file("/tmp/received2.txt").await;
    assert_eq!(
        received2, msg2,
        "Direction 2 failed: expected '{}', got '{}'",
        msg2, received2
    );
}

/// Test that message payload is preserved correctly
#[tokio::test]
async fn test_payload_integrity() {
    let container = setup_test_environment().await;

    container
        .start_listener("ns_receiver", TEST_PORT, "/tmp/received.txt")
        .await;

    container
        .start_relay(1, TEST_PORT, &["veth1b", "veth2b"])
        .await;

    // Send a message with various characters
    let test_message = "Hello World! Special chars: @#$%^&*() Numbers: 12345";
    container
        .send_broadcast("ns_sender", "10.0.1.255", TEST_PORT, test_message)
        .await;

    let received = container.read_file("/tmp/received.txt").await;

    assert_eq!(
        received, test_message,
        "Payload integrity failed: expected '{}', got '{}'",
        test_message, received
    );
}

/// Test that multiple packets are all relayed
#[tokio::test]
async fn test_multiple_packets() {
    let container = setup_test_environment().await;

    let cmd = format!(
        "ip netns exec ns_receiver sh -c 'socat -u UDP4-RECV:{},broadcast OPEN:/tmp/multi_received.txt,create,append 2> /tmp/socat_stderr.txt &'",
        TEST_PORT,
    );
    container.exec(&cmd).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    container
        .start_relay(1, TEST_PORT, &["veth1b", "veth2b"])
        .await;

    // Send multiple messages
    for i in 1..=3 {
        let msg = format!("MULTI_PACKET_{}", i);
        container
            .send_broadcast("ns_sender", "10.0.1.255", TEST_PORT, &msg)
            .await;
    }

    // Wait a bit more for all packets to arrive
    tokio::time::sleep(Duration::from_millis(100)).await;

    let received = container.read_file("/tmp/multi_received.txt").await;

    assert!(received.contains("MULTI_PACKET_1"));
    assert!(received.contains("MULTI_PACKET_2"));
    assert!(received.contains("MULTI_PACKET_3"));
}
