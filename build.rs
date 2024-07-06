use std::process::Command;

fn get_git_commit_info() -> (String, String) {
    // Used to extract latest HEAD commit hash and timestamp for the /info endpoint
    let output = Command::new("git")
        .args(["show", "HEAD", "-s", "--format=%H,%cI"])
        .output()
        .expect("Git command to get commit hash and timestamp should work during build process");

    let output_string =
        String::from_utf8(output.stdout).expect("Git command should produce valid string output");

    let (commit_hash, commit_timestamp) = output_string
        .as_str()
        .split_once(',')
        .expect("Git commit hash and timestamp string output should be comma separated");

    (commit_hash.to_string(), commit_timestamp.to_string())
}

fn get_git_remote_info() -> String {
    // Used to extract latest HEAD commit hash and timestamp for the /info endpoint
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .expect("Git command to get origin remote url should work during build process");

    let output_string =
        String::from_utf8(output.stdout).expect("Git command should produce valid string output");

    output_string
}

fn main() {
    let (commit_hash, commit_timestamp) = get_git_commit_info();
    let remote_url = get_git_remote_info();

    // Pass these 3 values as env var to the program
    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", commit_hash);
    println!("cargo:rustc-env=GIT_COMMIT_TIMESTAMP={}", commit_timestamp);
    println!("cargo:rustc-env=GIT_ORIGIN_REMOTE={}", remote_url);
}
