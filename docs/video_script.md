# 3-minute video script (rewrite in your own words)

Required: the problem, supporting data, the solution, and how it uses IBM Z (tech stack, LinuxONE instance, model). Everything below is backed by our results; don't add claims you can't show.

| Time | On screen | Say |
| --- | --- | --- |
| 0:00–0:25 | Samsung headline (2023); someone pasting a document into a chatbot | "In 2023, Samsung banned ChatGPT after engineers pasted internal code into it. LayerX's 2025 data shows about 18% of enterprise employees paste data into AI tools, and 22% of those pastes contain personal or payment data. The usual fix is redaction: hide the names. But is that enough?" |
| 0:25–0:50 | Demo page, step 2: basic redaction with the clues highlighted | "Here the name and NRIC are gone. But an AI can still tell she's a 34-year-old engineer in western Singapore with a master's degree. We measured it: after basic redaction, an AI attacker still worked out about two-thirds of people's personal details." |
| 0:50–1:35 | Demo page, steps 3–4: the rounds table, then "Passed" with labels like [AGE] and [JOB] | "So we attack our own redaction. An attacker AI tries to unmask the document and quotes exactly what gave it away. We remove exactly those phrases and attack again. If it still finds something after three rounds, the document goes to a human instead of being uploaded." |
| 1:35–2:15 | Terminal: `ssh` login, `uname -m` (s390x), `check_instance.sh` (z17), `shield.benchmark` running | "Everything runs on IBM LinuxONE, a z17: the detector, IBM's Granite model as the attacker, and the encrypted vault of real names. Raw documents never leave trusted hardware, not even to test the redaction. On three CPUs, a document takes about 100 seconds." |
| 2:15–2:45 | Results chart (three runs) | "We tested on 65 fake Singapore documents across three separate runs. Removing names and IDs left the attacker able to infer 64 to 66% of personal details. With our loop: 20 to 24%. About 80% of documents were cleared automatically; the rest were flagged for review." |
| 2:45–3:00 | Team name, repo link | "Attack-tested redaction: built on 2025 research, made private on LinuxONE. We're [team name]." |

## Checklist before recording
- [ ] Team name filled in (title of the submission must include it)
- [ ] Demo page running on LinuxONE (`python3 api.py`), viewed through the SSH tunnel; speed up the waiting parts in editing
- [ ] Say once that the test documents are fake, on purpose
- [ ] Don't claim the Telum AI accelerator or Secure Execution: neither is used
- [ ] Under 3 minutes
