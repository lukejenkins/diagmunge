# QSH-trace masksets measured across modems, and their union

> [!WARNING]
> ## ⚠️ NO WARRANTY. USE AT YOUR OWN RISK. ⚠️
>
> **These masksets are provided "AS IS", WITHOUT WARRANTY OF ANY KIND, express
> or implied.** They were found by **trial and error** on five modems. They are
> **not** from the chipset vendor, Quectel, Foxconn, Dell or any other vendor. No vendor
> has reviewed, endorsed or documented them, and nobody outside this project
> knows what the SSIDs or levels mean.
>
> Arming one sends an undocumented DIAG command to your modem's baseband.
> It may do nothing on your firmware. It may produce a large volume of trace
> data. It may behave in ways that were never seen during testing. It may
> do things to your modem, your carrier connection, or your data plan
> that the authors did not anticipate and cannot fix. **The authors accept no
> liability for any of it.** If you are not prepared to power-cycle or replace
> the modem, do not arm it.
>
> You are responsible for making sure that capturing baseband diagnostics is
> lawful where you are and permitted by your carrier and device agreements.

## What this is

A QSH-trace maskset is a list of `(ssid, level)` pairs. Sending it in a
`0x9001` SET tells the modem to emit `0x9D` QSH-trace frames for those
subsystems. `qsh_maskset_measured.json` holds one maskset per modem measured:

| profile | modem | chipset | pairs |
|---|---|---|---|
| `rm500q-ae` | Quectel RM500Q-AE | SDX55 | 15 |
| `t99w175` | Foxconn T99W175 | SDX55 | 15 |
| `rm520n-gl` | Quectel RM520N-GL | SDX62 | 16 |
| `t99w640-retail` | Foxconn T99W640, retail unit | SDX72 | 11 |
| `t99w640-engineering-sample` | Foxconn T99W640, engineering sample | SDX72 | 20 |
| **`union`** (default) | all of the above | SDX55, SDX62, SDX72 | 28 (computed) |

**Use `union` unless you have measured your own modem.** It is the default, and
it is what diaggulp arms when it is given no other maskset. Its public name
there is `measured-union`; each profile above is `measured-<profile>`.

Load one from Python:

```python
from diagmunge.qsh_maskset import bundled_maskset, union_maskset
pairs = bundled_maskset()              # the union, same as union_maskset()
pairs = bundled_maskset("rm520n-gl")   # one modem's pairs
```

Arm it with `diag_cmd.build_qsh_trace_maskset_set(pairs)`. Disarm with an
empty maskset (`build_qsh_trace_maskset_set(())`).

## How the masksets were made

No vendor file, vendor document or vendor tool was used. Everything below
was learned by sending commands to the modems and watching what came back.
It took four steps: learn the command's rules, learn to read the wire, measure
each modem, and combine the measurements.

### 1. The rules of the command, found by probing

| probe | result |
|---|---|
| 111 pairs in one SET | rejected (status 1); 110 is the most one SET accepts |
| `ssid = 0` | rejected (status 1) |
| SSIDs out of ascending order | rejected (status 1) |
| SSIDs the modem does not implement, at any level | accepted, silently ignored |
| an empty SET | accepted; the `0x9D` stream stops (this is the disarm) |
| SET 1..110, then a second SET with no disarm | the first SET's frames stop |

The last row matters most: **a SET replaces the armed maskset; it does not
add to it.** On a T99W640 the stream went from 373 frames/s to 0 when a SET of
111..220 followed a SET of 1..110. Both SDX55 parts and the SDX62 part did the
same when a SET naming only SSID 250 followed 1..110. So you cannot get past
the 110-pair limit by sending SETs back to back. Each window of SSIDs has to be
measured on its own, and whatever you finally arm has to fit in one SET.

### 2. The wire tells you what to arm

Every `0x9D` frame carries a 16-bit word at offset 2. Bits 13..6 are the
`subsys_id`, and bits 5..1 are the `sub_stream`. The `subsys_id` is the SSID
that was armed, and `sub_stream` is the bit number inside that SSID's
`level`. So the modem's own output says which pairs are live: for each
`subsys_id` seen, OR together `1 << sub_stream` for every sub-stream seen,
and you have a maskset that re-arms exactly that.

### 3. Measuring each modem

Each profile is the OR of two measurements made on that modem.

**a. The windowed sweep** (`qsh_maskset_discover`). For each SSID window in
turn, 1..110, then 111..220, then 221..255:

1. Arm every SSID in the window at `level = 0xFFFF` (all bits).
2. Wait 1 s for the arm to take effect.
3. Record every `(subsys_id, sub_stream)` on the wire for 15 s.
4. Disarm with an empty SET.

At the end, disarm again and check that the stream stays quiet.

**b. The all-bits capture.** A 20 s capture armed with SSIDs 1..110 at
`0xFFFF`, reading the same `(subsys_id, sub_stream)` pairs from every `0x9D`
frame. It catches subsystems that happened to be quiet during the sweep's
15 s window.

The first two T99W640 units were measured with the sweep alone:

| unit | 1..110 | 111..220 | 221..255 | result |
|---|---|---|---|---|
| T99W640 retail | 6,128 frames, 7 subsystems | 1 frame (SSID 119) | none | 8 pairs |
| T99W640 engineering sample | 41,288 frames, 18 subsystems | 395 frames (SSIDs 113, 122) | 167 frames (SSID 76 only) | 20 pairs |

The next day the RM500Q-AE, T99W175 and RM520N-GL were measured both ways,
and the T99W640 retail unit was measured again. The re-measure found three
SSIDs (18, 97, 115) and one more sub-stream bit that the first sweep missed,
and kept everything the first sweep had found. The `t99w640-retail` profile is
that re-measure, so it contains the first one.

### 4. Combining them: the union

A maskset measured on one model mostly misses another model's subsystems.
The first T99W640 retail maskset (8 pairs), armed on the other three modems,
caught only 4 or 5 subsystems each. So the default is not any single profile but their union: for
every SSID in any profile, OR together its levels. The loader computes it each
time, so it cannot drift from the profiles it is made of.

The union is safe to arm on any of these modems:

- **SSIDs a modem does not implement are accepted and ignored**, at any level.
- **Extra sub-stream bits are harmless.** The plain sweep arms every SSID in
  1..110 at `0xFFFF` (all bits), and every modem above accepted it with status 0.
- **It fits in one SET.** 28 pairs is well under the 110-pair limit, and they
  are sorted by SSID, which the modem requires.

### 5. Checking it

The union was armed on four of the modems with the published build of
diaggulp and compared, on the same day, with the first T99W640 retail maskset
(8 pairs, which was the default before the union) and with a maskset measured
on that modem. Each run was a 20 s capture, and every
modem was disarmed afterwards, with the disarm checked on the stream.

| modem | first T99W640 retail maskset | **`union`** | a maskset measured on that modem |
|---|---|---|---|
| RM500Q-AE | 685 frames, 4 subsystems | **49,088 frames, 12 subsystems** | 65,629 frames, 12 subsystems |
| T99W175 | 75–182 frames, 4–5 subsystems | **10,637 frames, 11 subsystems** | 10,379–11,173 frames, 14 subsystems |
| RM520N-GL | 578 frames, 4 subsystems | **12,112 frames, 13 subsystems** | 10,868 frames, 14 subsystems |
| T99W640 retail | 8,229 frames, 6 subsystems | **10,608 frames, 8 subsystems** | 8,216 frames, 9 subsystems |

On every modem the union came close to that modem's own measurement, and on
the T99W640 it beat the maskset first measured on that very unit.

## What was learned on the way

- **The RM520N-GL (SDX62) emits SSID 76 under any non-empty maskset**, even one
  that does not name it. SSID 76 looks like the QSH subsystem reporting on
  itself. Only the empty disarm stops it. That is why SSID 76 shows up in
  sweep windows that do not contain it.
- **Some subsystems sit above 110**: SSID 113 on the RM520N-GL and one T99W640,
  115 and 119 on the T99W640 retail unit. The 1..110 sweep cannot reach them;
  the union includes them.
- **The T99W175 delivers DIAG in bursts about 1.27 s apart.** Any check that
  waits for the stream to go quiet must wait longer than that.
- **The same modem gives different answers on different days.** The T99W640
  retail unit gave 8 pairs one day and 11 the next.

## Known limits

- **It only knows what was active during the dwell.** All the modems sat
  stationary and mostly idle. Subsystems that fire only on handover, NR
  attach, calls or other events may be missing.
- **Only four models were tested.** On another modem, the union is a guess
  that is more likely to be useful than any single profile. A maskset
  measured on your own modem is better still.
- **SSID 119 in the T99W640 retail profile rests on one frame** in the first
  sweep. The modem ignores SSIDs that send nothing, so keeping it costs nothing.
- Older chipsets (SDX20/SDX24) do not support the command at all and answer
  status 2.

## Measuring your own

`diagmunge.qsh_maskset` has the pieces for running the same sweep against
your own modem:

- `sweep_windows()` gives the SSID windows.
- `sweep_pairs(window)` gives the all-bits maskset for one window.
- `wire_key(frame)` reads `(subsys_id, sub_stream)` from a `0x9D` frame.
- `derive_pairs(observed)` turns what you saw into a maskset.

Arm each window alone, count, disarm, and move on. Write the result as
`{"pairs": [[ssid, level], ...]}` and diaggulp will arm it with
`--qsh-pairs-file`. The same no-warranty terms apply to anything you arm with
them.

## License

The maskset data in `qsh_maskset_measured.json` and this document are part of
diagmunge and are licensed under the Apache License, Version 2.0, like the
rest of the package. See `LICENSE` and `NOTICE` at the package root.

Section 7 of that license applies to these masksets in full:

```
7. Disclaimer of Warranty. Unless required by applicable law or
   agreed to in writing, Licensor provides the Work (and each
   Contributor provides its Contributions) on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   implied, including, without limitation, any warranties or conditions
   of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
   PARTICULAR PURPOSE. You are solely responsible for determining the
   appropriateness of using or redistributing the Work and assume any
   risks associated with Your exercise of permissions under this License.
```
