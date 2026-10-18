"""Make fake Singapore documents where we KNOW the truth about each person.

Each record:
  text      the document (HR email, clinic referral, or chat message)
  profile   the answer key: age, sex, region, occupation, education, relationship
            (+ the fake name/NRIC/phone/etc. used)
  revealed  which attributes the text actually contains a clue for. We only score the
            attacker on these: you can't "protect" something that was never there.

All people are fake. NRICs have valid check letters but are randomly generated.

    python -m shield.data_gen --n 100 --seed 1 --out data/dev.jsonl    # tune prompts on this
    python -m shield.data_gen --n 200 --seed 2 --out data/test.jsonl   # report results on this

Keep dev and test separate: if you tune prompts while looking at the test set, your final
numbers are optimistic (the same idea as not training on the test set).
"""
import argparse
import json
import random
from pathlib import Path

from .detector import nric_check_letter
from .schema import CURRENT_YEAR, PLACE_REGION

FIRST_NAMES = {
    "female": ["Rachel", "Mei Ling", "Hui Min", "Jia Hui", "Shermaine", "Grace"],
    "male": ["Wei Ming", "Jun Jie", "Marcus", "Daniel", "Zhi Hao", "Ryan"],
}
MALAY = {"female": ["Nurul Aisyah", "Siti", "Farah"], "male": ["Hafiz", "Irfan", "Syafiq"]}
INDIAN = {"female": ["Priya", "Kavitha", "Divya"], "male": ["Arun", "Vikram", "Suresh"]}
SURNAMES = ["Tan", "Lim", "Lee", "Ng", "Ong", "Wong", "Goh", "Chua", "Koh", "Teo"]
FATHER_NAMES = ["Rahman", "Osman", "Ismail", "Kumar", "Raman", "Rajan"]

STREET_SUFFIX = ["Avenue 3", "Street 21", "Road", "Drive", "Central"]

OCCUPATION_CLUES = {
    "engineer": ["{S} works as a site engineer on the Tuas plant retrofit.",
                 "{S} is our only lead engineer on the MRT signalling project."],
    "healthcare": ["{S} works as a staff nurse and covers the night shifts on Ward 7.",
                   "{S} is a pharmacist at a retail chain."],
    "teacher": ["{S} teaches Secondary 3 maths and is busy marking prelim papers.",
                "{S} has been a lecturer for six years."],
    "finance": ["{S} works as an auditor and is swamped during the March closing.",
                "{S} is an accountant at a logistics firm."],
    "it": ["{S} is a software developer on the payments team.",
           "{S} works in IT support for the whole building."],
    "service": ["{S} runs a hawker stall selling chicken rice.",
                "{S} works as a barista at the mall."],
    "manager": ["{S} is the operations manager for the Jurong warehouse.",
                "{S} was recently promoted to regional director."],
    "student": ["{S} is a final-year undergraduate.",
                "{S} is still a poly student doing an internship."],
}
EDUCATION_CLUES = {
    "postgraduate": ["{S} only finished {pos} part-time master's in March.",
                     "{S} is completing a PhD on weekends."],
    "bachelor": ["{S} graduated from NUS two years ago.",
                 "{S} completed {pos} NTU degree while working."],
    "diploma": ["{S} has a diploma from Ngee Ann Poly.",
                "{S} finished polytechnic before starting work."],
    "secondary": ["{S} left school after O levels.",
                  "{S} studied at ITE before joining us."],
}
RELATIONSHIP_CLUES = {
    "married": ["{Pos} {partner} usually picks {obj} up after work.",
                "{S} also needs to care for {pos} in-laws."],
    "divorced": ["Things have been hard for {obj} since the divorce.",
                 "{S} shares custody with {pos} ex-{partner}."],
    "widowed": ["{S} has been managing alone since {pos} late {partner} passed away.",
                "{S} has been a {widow} for two years."],
    "single": ["{Pos} {date} has been helping with the move.",
               "{S} mentioned {subj} is single and happy to travel."],
}
AGE_CLUES = ["{S} just turned {age} last month.", "{S} was born in {year}.",
             "As a {age}-year-old, {subj} is one of the younger staff here."]
REGION_CLUES = ["{S} lives in {place} and takes the bus in every morning.",
                "The clinic near {pos} flat in {place} has evening slots.",
                "{S} recently moved to {place} to be near family."]
DOC_TYPES = ["hr_email", "clinic_note", "chat"]


def _nric(rng: random.Random, birth_year: int) -> str:
    prefix = "T" if birth_year >= 2000 else "S"
    digits = f"{birth_year % 100:02d}{rng.randint(0, 99999):05d}"
    return prefix + digits + nric_check_letter(prefix, digits)


def make_profile(rng: random.Random) -> dict:
    sex = rng.choice(["female", "male"])
    occupation = rng.choice(list(OCCUPATION_CLUES))
    age = rng.randint(18, 24) if occupation == "student" else rng.randint(23, 68)
    education = (rng.choice(["diploma", "bachelor"]) if occupation == "student"
                 else rng.choice(list(EDUCATION_CLUES)))
    relationship = ("single" if age < 25 else rng.choice(list(RELATIONSHIP_CLUES)))
    place = rng.choice(list(PLACE_REGION))

    group = rng.choice(["chinese", "chinese", "malay", "indian"])
    if group == "chinese":
        first = rng.choice(FIRST_NAMES[sex])
        name = f"{first} {rng.choice(SURNAMES)}" if " " not in first else f"{rng.choice(SURNAMES)} {first}"
    else:
        first = rng.choice((MALAY if group == "malay" else INDIAN)[sex])
        link = {"malay": {"female": "binte", "male": "bin"},
                "indian": {"female": "d/o", "male": "s/o"}}[group][sex]
        name = f"{first} {link} {rng.choice(FATHER_NAMES)}"
    birth_year = CURRENT_YEAR - age
    return {
        "name": name, "first_name": first,
        "nric": _nric(rng, birth_year),
        "phone": f"+65 {rng.choice('89')}{rng.randint(100, 999)} {rng.randint(1000, 9999)}",
        "email": f"{first.split()[0].lower()}.{rng.randint(10, 99)}@example.com",
        "address": f"Blk {rng.randint(100, 899)} {place} {rng.choice(STREET_SUFFIX)}",
        "unit": f"#{rng.randint(2, 20):02d}-{rng.randint(10, 400)}",
        "postal": f"Singapore {rng.randint(100000, 829999)}",
        "bank": rng.choice([
            f"DBS account {rng.randint(100, 999)}-{rng.randint(10000, 99999)}-{rng.randint(0, 9)}",
            f"OCBC a/c {rng.randint(100, 999)}-{rng.randint(100000, 999999)}-{rng.randint(1, 999):03d}",
            f"POSB savings account {rng.randint(10**9, 10**10 - 1)}",
        ]),
        "age": age, "birth_year": birth_year, "sex": sex, "place": place,
        "region": PLACE_REGION[place], "occupation": occupation,
        "education": education, "relationship": relationship,
    }


def _fill(sentence: str, p: dict) -> str:
    female = p["sex"] == "female"
    words = {
        "S": "She" if female else "He", "subj": "she" if female else "he",
        "Pos": "Her" if female else "His", "pos": "her" if female else "his",
        "obj": "her" if female else "him", "partner": "husband" if female else "wife",
        "widow": "widow" if female else "widower", "date": "boyfriend" if female else "girlfriend",
        "age": p["age"], "year": p["birth_year"], "place": p["place"],
    }
    return sentence.format(**words)


def make_document(rng: random.Random, p: dict, doc_type: str, clue_rate: float = 0.8) -> dict:
    clue_banks = {
        "age": AGE_CLUES, "region": REGION_CLUES,
        "occupation": OCCUPATION_CLUES[p["occupation"]],
        "education": EDUCATION_CLUES[p["education"]],
        "relationship": RELATIONSHIP_CLUES[p["relationship"]],
    }
    revealed = ["sex"]                       # pronouns appear in every document
    clues = []
    for attribute, bank in clue_banks.items():
        if rng.random() < clue_rate:
            revealed.append(attribute)
            clues.append(_fill(rng.choice(bank), p))
    rng.shuffle(clues)
    body = " ".join(clues)
    obj = "her" if p["sex"] == "female" else "him"

    if doc_type == "hr_email":
        text = (f"Hi team,\n\nFollowing up on {p['name']}'s request for flexible working hours "
                f"(NRIC {p['nric']}). {body}\n\nPlease contact {p['first_name']} at {p['phone']} "
                f"or {p['email']} to confirm the new roster. Any back pay goes to {p['bank']}."
                f"\n\nThanks,\nHR Operations")
    elif doc_type == "clinic_note":
        text = (f"Referral note\nPatient: {p['name']}, NRIC {p['nric']}\n"
                f"Address: {p['address']}, {p['unit']}, {p['postal']}\n\n"
                f"Patient presents with recurring migraines over the past month. {body}\n\n"
                f"Review in two weeks. Contact: {p['phone']}.")
    else:
        text = (f"hey, quick update about {p['name']}. {body} "
                f"{p['first_name']} said to text {obj} at {p['phone']} if anything changes. "
                f"also the deposit refund should go to {p['bank']}")
    return {"doc_type": doc_type, "text": text, "revealed": revealed}


def generate(n: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    records = []
    for i in range(n):
        profile = make_profile(rng)
        doc = make_document(rng, profile, DOC_TYPES[i % len(DOC_TYPES)])
        records.append({"id": f"s{seed}-{i:04d}", **doc, "profile": profile})
    return records


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default="data/dev.jsonl")
    args = ap.parse_args()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for r in generate(args.n, args.seed):
            f.write(json.dumps(r) + "\n")
    print(f"Wrote {args.n} documents to {out}")


if __name__ == "__main__":
    main()
