# Development and public releases

`origin` is `oguzhanoztaskin/hybrid-vpn-priv`: all development branches and full history belong
there. `publish` is `oguzhanoztaskin/hybrid-vpn`: only explicitly requested public releases go there.
The local default push remote is origin. Install the public-push guard in a fresh checkout:

```sh
git config remote.pushDefault origin
git config core.hooksPath .githooks
```

Development pushes do not publish APKs or trigger a public release. Never push a development branch,
all branches, or all tags to publish. Every public release is one snapshot commit on release/public;
the first snapshot has no parent, subsequent snapshots have only the previous public release as
parent. Development commit messages and ancestry are absent from that history.

## Explicit release procedure

1. Obtain the user's explicit release instruction. Commit verified source, update the version,
   CHANGELOG and test plan, and back up all development branches/tags to origin.
2. Run the repository's required checks and device checks. Keep all credentials, signing keys,
   tsnet state, local.properties and build outputs out of source control.
3. Build installable APKs only for this public release:

   ```sh
   scripts/build-public-apks.sh X.Y.Z
   ```

   This produces ARM64, x86_64 and universal APKs plus SHA256SUMS under
   build/public-release/vX.Y.Z. The universal APK contains both supported ABIs; 32-bit ARM/x86 are
   not supported by the bundled engine. APKs currently use the experimental debug signing identity,
   matching the tested phone builds. Preserve that private keystore for compatible updates and
   describe the experimental signing/build status in release notes. Never upload the keystore.
4. Prepare the public snapshot, without checking it out or pushing it:

   ```sh
   scripts/prepare-public-release.sh X.Y.Z verified-source-ref
   ```

   The helper checks a clean worktree/version and refuses to move an existing tag. It creates an
   annotated vX.Y.Z tag pointing to the new snapshot. Back up release/public and this tag to origin.
5. After the explicit release instruction, push only the release snapshot and its tag:

   ```sh
   HYBRIDVPN_PUBLISH_RELEASE=1 git push publish release/public:main refs/tags/vX.Y.Z
   ```

   The pre-push hook rejects other refs and accidental public pushes. An initial history replacement
   additionally needs explicit authorization, exact --force-with-lease values for the old refs, and
   HYBRIDVPN_PUBLISH_REPLACE_HISTORY=1 for deleting development refs/old development-history tags.
   Back up those original refs privately first. Do not use broad --force or --mirror.
6. Create the explicitly requested GitHub release and upload only the three APKs and SHA256SUMS.
   Do not add CI that publishes on ordinary pushes. GitHub API access must be authenticated to an
   account that can manage the publish repository; Git SSH access alone does not create releases.

The public repository's source archive comes from the snapshot tag. Native dependencies are fetched
by the existing checksum-pinned scripts; APKs include their compiled libraries. Public source never
contains private development history, application state or signing material.
