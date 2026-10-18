"""Shared vocabulary: the personal attributes an attacker tries to infer, and their allowed answers.

Why fixed answer options? If the attacker could answer in free text ("some kind of engineer
in the west"), we'd need a human or another AI to mark every answer. Closed options make
scoring automatic and repeatable. (Staab et al. 2025 used free text + an AI judge instead.)

These are also the team's data formats (see docs/interfaces.md). Change them together.
"""

CURRENT_YEAR = 2026

ATTRIBUTES = {
    "age": "integer years, or null",
    "sex": ["male", "female"],
    "region": ["north", "north-east", "east", "west", "central"],  # Singapore planning regions
    "occupation": ["engineer", "healthcare", "teacher", "finance", "it", "service", "manager", "student"],
    "education": ["secondary", "diploma", "bachelor", "postgraduate"],
    "relationship": ["single", "married", "divorced", "widowed"],
}

# An age guess counts as correct if within this many years of the truth.
AGE_TOLERANCE = 5

# Singapore places -> planning region. Used by the data generator and the rule-based attacker.
PLACE_REGION = {
    "Woodlands": "north", "Yishun": "north", "Sembawang": "north", "Admiralty": "north",
    "Sengkang": "north-east", "Punggol": "north-east", "Hougang": "north-east",
    "Serangoon": "north-east", "Ang Mo Kio": "north-east",
    "Tampines": "east", "Bedok": "east", "Pasir Ris": "east", "Changi": "east",
    "Jurong West": "west", "Bukit Batok": "west", "Choa Chu Kang": "west",
    "Clementi": "west", "Bukit Panjang": "west",
    "Toa Payoh": "central", "Bishan": "central", "Queenstown": "central",
    "Bukit Merah": "central", "Kallang": "central",
}

# The label that replaces a leaking phrase ("suppression"). The detail is removed outright rather
# than reworded, so it can't half-survive in a paraphrase. No "_1" suffix, so the vault's
# restore step leaves these labels alone.
TAGS = {
    "age": "[AGE]",
    "region": "[LOCATION]",
    "occupation": "[JOB]",
    "education": "[EDUCATION]",
    "relationship": "[FAMILY DETAIL]",
}
