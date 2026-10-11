<div align="center">

<img src="docs/media/scenes/01-hero-tracker-sm.jpg" alt="A Kuwaiti tracker reads footprints in the sand at dawn" width="672">

# قصّاص Qassas

**Read the trace. Prove every step.**

Open digital forensics and incident response education for Kuwait and the Gulf, in Arabic and English.

[qassas.3li.info](https://qassas.3li.info) · [العربية](#العربية)

</div>

Qassas is named after the *qassas al-athar*, the trackers of Kuwait and Arabia who read a single footprint
and knew who had passed, how fast and how long ago. It teaches the same patience for the digital trail:

- **15 bilingual modules**, about 38 hours, from first principles to the expert report, each with a lesson,
  steps, common mistakes, a note on Kuwaiti law and a quiz.
- **A practice case** built from synthetic evidence: a phishing email, a leaked tender and a morning of logs,
  shortcuts, browser history and network traffic to reconstruct. Twelve questions, graded by hash.
- **Six labs that run in the browser**: fingerprints, file signatures, photo metadata with the nearest
  Kuwaiti area, a custody log you can break, the case timeline and the case check.
- **A toolkit** in Python with no dependencies that does everything the site teaches, and an **MCP server**
  so AI assistants can use the same tools, read only.
- **A legal register** of 35 laws, rulings and standards across Kuwait, the GCC and international bodies,
  each linked to its source.
- **An explainer video** in Arabic and English, made with Higgsfield and narrated with ElevenLabs.

<p align="center"><img src="docs/media/scenes/poster-06-timeline-sm.jpg" alt="One timeline for every source" width="560"></p>

## Quick start

```sh
pipx install git+https://github.com/SiteQ8/Qassas      # Python 3.9 or newer, nothing else
qassas lab make --out qassas-case-01                    # write the practice case
qassas manifest verify qassas-case-01/manifest.json --root qassas-case-01/evidence
qassas report qassas-case-01 --lang ar --out report-ar.md
```

Or run it from a clone without installing: `python3 -m qassas --help`.

## The toolkit

| Command | What it does |
|---|---|
| `qassas hash FILE...` | MD5, SHA-1 and SHA-256 in one pass |
| `qassas manifest create\|verify` | Hash every evidence file and check nothing changed, also as `sha256sum -c` |
| `qassas custody add\|show\|verify LOG` | A hash chained chain of custody log that names the exact entry someone edited |
| `qassas identify PATH` | Identify files by content and flag names that lie about their type |
| `qassas carve IMAGE [OUT]` | Carve JPEG, PNG, GIF, PDF and ZIP from raw data, walking JPEG markers so thumbnails do not cut photos |
| `qassas meta FILE...` | EXIF with GPS and the nearest Kuwaiti area, PNG text, PDF info and revisions, Office properties |
| `qassas strings FILE` | ASCII, UTF-8 and UTF-16 strings that find Arabic, plus URLs, emails, IPv4, Kuwaiti mobiles and IBANs |
| `qassas browser HISTORY` | Chromium and Firefox visits, downloads and searches, read from a copy |
| `qassas lnk FILE...` | Windows shortcut target, times and volume |
| `qassas logs FILE` | Linux auth.log or exported Windows events, with guessing, guess then success, cleared logs and risky sudo |
| `qassas pcap FILE` | DNS, TLS server names, HTTP, conversations and beaconing |
| `qassas timeline CASE` | Every source merged in UTC and shown in Kuwait time |
| `qassas report CASE --lang ar\|en` | A full examination report with the source of every finding |
| `qassas lab make\|check` | Write the practice case or grade your answers |
| `qassas glossary`, `qassas law` | Terms and laws in both languages |
| `qassas mcp --root DIR` | The MCP server |

### MCP server

Fourteen read only tools: identify, hash, metadata, strings, browser history, shortcuts, logs, pcap, custody,
manifest, full case examination, glossary, law and lessons. Every path is confined to `--root`.

```json
{
  "mcpServers": {
    "qassas": { "command": "qassas", "args": ["mcp", "--root", "/path/to/qassas-case-01"] }
  }
}
```

## The course

| | Module | | Module |
|---|---|---|---|
| 1 | Reading the trace | 9 | Logs and logins |
| 2 | The law in Kuwait and the Gulf | 10 | Memory forensics |
| 3 | At the scene | 11 | Network forensics |
| 4 | Imaging and hashing | 12 | Browsers and phishing |
| 5 | Chain of custody | 13 | Mobile devices |
| 6 | Files, signatures and carving | 14 | Building the timeline |
| 7 | Metadata: where and when | 15 | The report and the case |
| 8 | Windows artifacts | | |

## How it is built

```
qassas/            the toolkit, with its data: lessons, glossary, law, tools, signatures, the case
site/              site text and lab definitions
docs/              the website served by GitHub Pages
scripts/           build_site.py, check_lang.py, preflight.py
tools/explainer/   script, frames, narration and the builder for the explainer video
tests/, test/      Python tests, browser parity tests and the browser test suite
```

The rules the project holds itself to are tests, not conventions: every text exists in both languages, every
number in English survives into Arabic, Arabic periods only close sentences, no Unicode dashes, generated files
match their sources byte for byte, the practice case is reproducible byte for byte, the browser and Python give
the same hashes and answers, and every page renders in both languages on a phone and a desktop without errors.

```sh
python3 scripts/preflight.py
```

## Author

Ali AlEnezi is a senior security architect in Kuwait. He leads security architecture at the largest financial
institution in the country, chairs the Cyber Risk and Security Committee serving Kuwait and the Gulf, served on
the board of one of the largest information technology companies in Kuwait, and maintains a portfolio of open
source security tools for the region.

Code under the [MIT license](LICENSE). Lessons, images and narration under CC BY 4.0. See [NOTICE.md](NOTICE.md).

---

<div dir="rtl">

## العربية

# قصّاص

**اقرأ الأثر وأثبت كل خطوة**

قصّاص منصة تعليمية مفتوحة للتحليل الجنائي الرقمي والاستجابة للحوادث في الكويت والخليج بالعربية والإنجليزية.

سُمّي المشروع على اسم قصّاصي الأثر في الكويت والجزيرة العربية الذين كانوا يقرؤون أثر القدم الواحد فيعرفون من مرّ وبأي سرعة ومنذ متى وهو يعلّم الصبر نفسه في تتبع الأثر الرقمي.

- **خمس عشرة وحدة** بنحو 38 ساعة تبدأ من المبادئ الأولى وتنتهي بتقرير الخبير وفي كل وحدة درس وخطوات وأخطاء شائعة وملاحظة عن القانون الكويتي واختبار قصير
- **قضية تدريبية** مبنية على أدلة مصطنعة فيها رسالة تصيد ومناقصة مسرّبة وصباح كامل من السجلات والاختصارات وسجل التصفح وحركة الشبكة ومعها اثنا عشر سؤالاً تُصحَّح بالبصمات
- **ستة مختبرات تعمل في المتصفح** للبصمات وتواقيع الملفات وبيانات الصور مع أقرب منطقة كويتية وسجل حيازة يمكنك كسره والخط الزمني للقضية والتحقق من إجاباتها
- **مجموعة أدوات** بلغة Python بلا اعتماديات تنفّذ كل ما يعلّمه الموقع ومعها **خادم MCP** يتيح للمساعدات الذكية استخدام الأدوات نفسها للقراءة فقط
- **سجل قانوني** يضم 35 قانوناً وحكماً ومعياراً في الكويت ودول الخليج والهيئات الدولية وكل منها مرتبط بمصدره
- **فيديو تعريفي** بالعربية والإنجليزية صُنع باستخدام Higgsfield وسُجّل صوته باستخدام ElevenLabs بصوت راوٍ كويتي

### البدء السريع

```sh
pipx install git+https://github.com/SiteQ8/Qassas
qassas lab make --out qassas-case-01
qassas report qassas-case-01 --lang ar --out report-ar.md
```

كل الأدلة في المختبرات مصطنعة فالأشخاص والشركات والنطاقات مختلقة وتنتهي النطاقات بـ .example وتأتي العناوين من النطاقات المخصصة للتوثيق.

السجل القانوني مادة تعليمية وليس استشارة قانونية لذا راجع الجريدة الرسمية قبل الاعتماد على أي نص.

### المؤلف

علي العنزي مهندس معمارية أمن أول في الكويت يقود معمارية الأمن في أكبر مؤسسة مالية في البلاد ويرأس لجنة المخاطر والأمن السيبراني التي تخدم الكويت والخليج وكان عضواً في مجلس إدارة إحدى أكبر شركات تقنية المعلومات في الكويت ويرعى مجموعة من أدوات الأمن مفتوحة المصدر للمنطقة.

</div>
