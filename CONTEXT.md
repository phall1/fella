# Fella workspaces

Fella separates everyday work into persistent identities and workspaces.
Sessions are temporary visits to those environments.

## Language

**Identity**:
A named collection of application state and credentials shared by its workspaces.
It is not a forged person, device, OS account, or network origin.
_Avoid_: persona, mask

**Workspace**:
A named association between a project directory and an identity.
_Avoid_: desktop, sandbox image

**Session**:
One running shell or command in a workspace. Its identity and workspace do not
change during its lifetime.
_Avoid_: global active identity, hardened mode

**Identity home**:
The persistent home containing an identity's settings, credentials, history,
and user-installed tools.
_Avoid_: host home, ephemeral profile

**Project**:
The existing directory explicitly shared with a workspace's sessions.
_Avoid_: disposable checkout
