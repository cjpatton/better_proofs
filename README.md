# Better proofs

[Game-playing proofs](https://eprint.iacr.org/2004/331) written in Rust. A
"game" is a security definition for a cryptographic protocol (or primitive)
that is used to define an adversary's advantage in breaking the protocol.

Games are usually specified in "pseudocode". There is no standard syntax for
this pseudocode (each proof author has their own style), and its semantics is
usually only implicitly defined. By replacing this pseudocode with a proper
programming language, we hope to make it easier to interpret these definitions
and verify proofs for them.

We choose Rust because so that we can use with [hax](https://cryspen.com/hax/).
hax is a tool for translating code into languages with formal semantics such
that the code can be analyzed for functional correctness and various (symbolic)
security properties. In this way, hax can act as a bridge between experts in
formal methods and those designing and implementing protocols.

Concretely, we would like to use hax as follows. The definition, protocol, and
proof are all implemented in Rust by the proof author. Game-playing proofs
consist of a sequence of games, each derived from the previous game by
rewriting it or changing its functionality. For each such "transition", the
proof author argues that the neighboring games are (1) equivalent, (2)
identical until something rare happens, or (3) distinguishing between the games
reduces to breaking an assumption. The hope is that checking each of these
transitions amounts to an equivalence proof (modulo a branch of code); it is
the proof author's responsibility to compute bounds and specify reductions.

Disclaimer: I am a "pen-and-paper" person and don't have a formal methods
background. I'm aware that there are a number of tools out there (e.g.,
[CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/) for
establishing computational security proofs for cryptographic protocols. My
understanding is that using these tools, especially when they need to be
adapted to a new domain, requires a significant amount of expertise.
