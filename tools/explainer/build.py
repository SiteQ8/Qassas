#!/usr/bin/env python3
"""Build the Qassas explainer videos and their captions from versioned sources.

Inputs (all in this folder):
  script.json      the authored narration, split into scenes and caption cues
  words.json       word timestamps measured from each narration take by speech
                   recognition (faster-whisper small), used only for timing
  narration/*.mp3  the narration takes (Arabic and English)
  frames/*         one illustration per scene, plus an optional motion clip

Outputs (in docs/media/explainer):
  qassas-explainer-ar.mp4 / -en.mp4   1920x1080 H.264 with AAC narration
  qassas-explainer-ar.vtt / -en.vtt   captions taken from the authored text
  poster.jpg                          the first frame, for the video element

Caption wording always comes from script.json, never from the recognizer.
The recognizer only says when each cue starts. Every cue start is anchored to
the recognized word that best matches the cue's first word near its expected
position, so a scene never changes before its sentence is spoken.

Usage: python3 tools/explainer/build.py [--check]
--check verifies that the committed captions match what the sources produce.
"""
import difflib
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "docs", "media", "explainer")
W, H, FPS = 1920, 1080, 24
XFADE = 0.4
TAIL = 1.6  # seconds the last scene holds after the narration ends
LEAD = 0.18  # a cut lands this long before the first word of its sentence

DIACRITICS = re.compile(r"[ً-ْٰـ]")


def norm(word):
    word = DIACRITICS.sub("", word.lower())
    word = re.sub(r"[^\w؀-ۿ]", "", word)
    return word.replace("أ", "ا").replace("إ", "ا").replace("آ", "ا").replace("ة", "ه").replace("ى", "ي")


def duration(path):
    out = subprocess.check_output(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path])
    return float(out.decode().strip())


def anchor_times(cues, words):
    """Return the start time of every cue, in order."""
    authored = []
    starts = []
    for cue in cues:
        starts.append(len(authored))
        authored.extend(cue.split())
    total_a, total_w = len(authored), len(words)
    times, floor = [], 0
    for k, a_idx in enumerate(starts):
        if k == 0:
            times.append(0.0)
            continue
        expect = round(a_idx * total_w / total_a)
        target = norm(authored[a_idx])
        target2 = norm(authored[a_idx + 1]) if a_idx + 1 < total_a else ""
        best, best_score = None, -1.0
        for j in range(max(floor, expect - 8), min(total_w, expect + 9)):
            s1 = difflib.SequenceMatcher(None, target, norm(words[j][0])).ratio()
            s2 = difflib.SequenceMatcher(None, target2, norm(words[j + 1][0])).ratio() if target2 and j + 1 < total_w else 0
            score = s1 + 0.6 * s2 - 0.02 * abs(j - expect)
            if score > best_score:
                best, best_score = j, score
        floor = best + 1
        times.append(max(0.0, words[best][1] - LEAD))
    return times


def vtt_time(t):
    h, rem = divmod(t, 3600)
    m, s = divmod(rem, 60)
    return "%02d:%02d:%06.3f" % (h, m, s)


def build_captions(lang, script, words, audio_len):
    cues, scene_of_cue = [], []
    for i, scene in enumerate(script["scenes"]):
        for cue in scene[lang]:
            cues.append(cue)
            scene_of_cue.append(i)
    times = anchor_times(cues, words)
    lines = ["WEBVTT", "Kind: captions", "Language: " + lang, ""]
    for k, cue in enumerate(cues):
        start = times[k]
        end = times[k + 1] - 0.05 if k + 1 < len(cues) else audio_len
        lines += [str(k + 1), vtt_time(start) + " --> " + vtt_time(end), cue, ""]
    scene_starts = []
    for k, i in enumerate(scene_of_cue):
        if len(scene_starts) == i:
            scene_starts.append(times[k])
    return "\n".join(lines), scene_starts


def render(lang, script, scene_starts, audio, audio_len, out_path, tmp):
    total = audio_len + TAIL
    bounds = scene_starts + [total]
    segs = []
    for i, scene in enumerate(script["scenes"]):
        dur = bounds[i + 1] - bounds[i] + (XFADE if i + 1 < len(script["scenes"]) else 0)
        seg = os.path.join(tmp, "%s-%02d.mp4" % (lang, i))
        frame = os.path.join(HERE, "frames", scene["frame"] + ".png")
        frames = int(round(dur * FPS))
        # A slow push in on every still: 4 percent over the scene, centred.
        zoom = ("scale=%d:%d:flags=lanczos,zoompan=z='1+0.04*on/%d':x='iw/2-(iw/zoom/2)':"
                "y='ih/2-(ih/zoom/2)':d=%d:s=%dx%d:fps=%d" % (W * 2, H * 2, frames, frames, W, H, FPS))
        if scene.get("clip"):
            clip = os.path.join(HERE, "frames", scene["clip"])
            clip_len = duration(clip)
            hold = max(0.0, dur - clip_len)
            vf = ("[0:v]scale=%d:%d:flags=lanczos,fps=%d,setsar=1[a];"
                  "[a]tpad=stop_mode=clone:stop_duration=%.3f,trim=duration=%.3f[v]" % (W, H, FPS, hold, dur))
            cmd = ["ffmpeg", "-y", "-loglevel", "error", "-i", clip, "-filter_complex", vf, "-map", "[v]"]
        else:
            cmd = ["ffmpeg", "-y", "-loglevel", "error", "-loop", "1", "-i", frame,
                   "-vf", zoom + ",setsar=1", "-frames:v", str(frames)]
        cmd += ["-an", "-c:v", "libx264", "-preset", "medium", "-crf", "20", "-pix_fmt", "yuv420p", seg]
        subprocess.check_call(cmd)
        segs.append((seg, dur))

    inputs, filt, last, offset = [], [], "0:v", 0.0
    for seg, _ in segs:
        inputs += ["-i", seg]
    for i in range(1, len(segs)):
        offset += segs[i - 1][1] - XFADE
        label = "v%d" % i
        filt.append("[%s][%d:v]xfade=transition=fade:duration=%.2f:offset=%.3f[%s]" % (last, i, XFADE, offset, label))
        last = label
    filt.append("[%s]fade=t=in:st=0:d=0.5,fade=t=out:st=%.3f:d=0.8,format=yuv420p[vout]" % (last, total - 0.8))
    n = len(segs)
    filt.append("[%d:a]loudnorm=I=-16:TP=-1.5:LRA=11,apad=whole_dur=%.3f[aout]" % (n, total))
    cmd = (["ffmpeg", "-y", "-loglevel", "error"] + inputs + ["-i", audio, "-filter_complex", ";".join(filt),
           "-map", "[vout]", "-map", "[aout]", "-c:v", "libx264", "-preset", "slow", "-crf", "23",
           "-profile:v", "high", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", "-ar", "48000",
           "-movflags", "+faststart", "-t", "%.3f" % total, out_path])
    subprocess.check_call(cmd)


def main():
    check = "--check" in sys.argv
    script = json.load(open(os.path.join(HERE, "script.json"), encoding="utf-8"))
    words = json.load(open(os.path.join(HERE, "words.json"), encoding="utf-8"))
    os.makedirs(OUT, exist_ok=True)
    problems = []
    for lang, take in (("ar", "ar-2"), ("en", "en-2")):
        audio = os.path.join(HERE, "narration", lang + ".mp3")
        audio_len = duration(audio)
        vtt, scene_starts = build_captions(lang, script, words[take], audio_len)
        vtt_path = os.path.join(OUT, "qassas-explainer-%s.vtt" % lang)
        if check:
            current = open(vtt_path, encoding="utf-8").read() if os.path.exists(vtt_path) else ""
            if current != vtt:
                problems.append(vtt_path + " is stale")
            continue
        with open(vtt_path, "w", encoding="utf-8") as fh:
            fh.write(vtt)
        print(lang, "scene starts", [round(t, 2) for t in scene_starts])
        with tempfile.TemporaryDirectory() as tmp:
            render(lang, script, scene_starts, audio, audio_len,
                   os.path.join(OUT, "qassas-explainer-%s.mp4" % lang), tmp)
    if not check:
        subprocess.check_call(["ffmpeg", "-y", "-loglevel", "error", "-i",
                               os.path.join(HERE, "frames", "02-tracker.png"),
                               "-vf", "scale=1280:-2:flags=lanczos", "-q:v", "4", os.path.join(OUT, "poster.jpg")])
    if problems:
        print("\n".join(problems))
        sys.exit(1)
    print("explainer ok")


if __name__ == "__main__":
    main()
