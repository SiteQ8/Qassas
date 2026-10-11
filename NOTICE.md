# Notice

## Code

The Python toolkit, the site code and the build scripts are released under the MIT license in [LICENSE](LICENSE).

## Lessons, images and narration

The lessons, glossary, case text, images, video and narration are released under
[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).
Credit "Qassas, Ali AlEnezi" with a link to https://qassas.3li.info when you reuse them.

## How the media was made

- Photographic scenes (`docs/media/scenes/01` to `12`) and the poster style key frames
  (`tools/explainer/frames`) were generated with Higgsfield. The poster frames use the
  Poster Vector explainer style, and one frame was animated with Higgsfield video.
- The Arabic narration was voiced with ElevenLabs using a Kuwaiti narrator voice, and the
  English narration with a documentary voice.
- `tools/explainer/build.py` assembles both explainer videos and writes their captions from
  `tools/explainer/script.json`. Caption wording comes from the authored script. Speech
  recognition was used only to time each line.

## Practice evidence

Every file under `docs/labs` and everything `qassas lab make` writes is synthetic. The
company, people, domains and addresses are invented. Domains end in `.example` and IP
addresses come from the documentation ranges in RFC 5737, so nothing points at a real system.

## Legal register

`qassas/data/legal.json` summarises laws and standards for teaching. It is not legal advice.
English research notes were checked against the sources linked in each entry on the date
recorded in the changelog. Check the official gazette before relying on any provision.

## Fonts

Alexandria, Readex Pro and JetBrains Mono are used under the SIL Open Font License 1.1,
see [docs/fonts/OFL.txt](docs/fonts/OFL.txt).

## Third party tools

The tool catalogue links to independent open source projects. Their names belong to their
authors, and their licenses were read from each repository on the date in `qassas/data/tools.json`.
