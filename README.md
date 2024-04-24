# Better proofs

Game-playing proofs [BR06] written in Rust. A "game" is a security definition
for a cryptographic protocol (or primitive) that is used to define an
adversary's advantage in breaking the protocol.

## Why

Games are usually specified in "pseudocode". There is no standard syntax for
this pseudocode (each proof author has their own style), and its semantics is
usually only implicitly defined. By replacing this pseudocode with a proper
programming language, we can make it easier to interpret these definitions
and verify proofs for them with the help of a computer.

There are already a number of tools for establishing game-playing proofs, such
as [CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/) or
[SSProve](https://eprint.iacr.org/2021/397)). With these tools, one normally
carries out the proof work in a language specific to the tool, which requires a
high degree of expertise.

[hax](https://cryspen.com/hax/) is a tool for translating Rust into languages
with formal semantics such that the code can be analyzed for functional
correctness and various (symbolic) security properties. In this way, hax can
act as a bridge between experts in formal methods and those designing and
implementing protocols.

We envision the following separation of concerns. The definition, protocol, and
proof are all implemented in Rust. The proof consists of a sequence of games,
each derived from the previous game by rewriting it or changing its
functionality. For each such "transition", we need to (1) argue that the games
are equivalent, (2) argue that the games are equivalent until something rare
happens ("identical until bad"), or (3) construct a reduction of a
distinguisher to an algorithm that breaks one of our assumptions. The hope is
that the task of formally verifying each of these transitions can be formulated
as checking equivalence of two Rust programs (i.e., neighboring games), thereby
reducing the amount of work we need the formal methods tools to do.

There are a few reasons why doing most of the proof work in Rust, rather than
in the language native to the tool, may not work:

1. The formal methods expert may need domain expertise in order to verify game
   hops. Put another way, it may be more efficient for the domain expert to
   just learn the damn tools!

2. The concrete cost (in terms of CPU time and memory) of finding a proof might
   be higher than if the games were expressed in native code.

3. It may be harder to find a proof for translated code compared to native
   code.

This repo can be thought of an experiment to assess these costs.

## What

The crate has two modules, each containing a toy example to get us started:

- `prf` defines secure PRFs and gives a proof sketch of the PRP/PRF switching
  lemma [BR06] consisting of a sequence of game transitions.

- `vdaf` defines security properties of VDAFs [draft-irtf-cfrg-vdaf]. It also
  gives two constructions, one of which is trivially private, but not robust,
  and another that is trivially robust, but not private. The proofs *should* be
  simple :)

[BR06]: https://eprint.iacr.org/2004/331
[draft-irtf-cfrg-vdaf]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf
