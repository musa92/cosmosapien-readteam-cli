"""
Taxonomy of manipulation tactics commonly used in deceptive practices.
For research and classification purposes only.
"""
from enum import Enum

class ManipulationTactic(Enum):
    MISDIRECTION = "MISDIRECTION"
    CONCEALMENT = "CONCEALMENT"
    FABRICATION = "FABRICATION"
    DEFLECTION = "DEFLECTION"
    GASLIGHTING = "GASLIGHTING"
    MINIMIZATION = "MINIMIZATION"
    RATIONALIZATION = "RATIONALIZATION"
    CHARM = "CHARM"
    INTIMIDATION = "INTIMIDATION"
    PATTERN_DISRUPTION = "PATTERN_DISRUPTION"

TACTIC_DEFS = {
    ManipulationTactic.MISDIRECTION: {
        "label": "Red Herring Strategy",
        "aka": ["distraction", "attention diversion", "false focus"],
        "definition": "Intentionally introducing irrelevant information or topics to divert attention from critical issues"
    },
    ManipulationTactic.CONCEALMENT: {
        "label": "Evidence Suppression",
        "aka": ["information hiding", "data obfuscation", "selective omission"],
        "definition": "Deliberate withholding or obscuring of relevant information to prevent detection or analysis"
    },
    ManipulationTactic.FABRICATION: {
        "label": "False Evidence Construction",
        "aka": ["artificial creation", "synthetic data generation", "false documentation"],
        "definition": "Creation of artificial or false information to support deceptive narratives"
    },
    ManipulationTactic.DEFLECTION: {
        "label": "Blame Shifting",
        "aka": ["responsibility transfer", "scapegoating", "attribution shift"],
        "definition": "Redirecting responsibility or blame to other parties to avoid accountability"
    },
    ManipulationTactic.GASLIGHTING: {
        "label": "Psychological Manipulation",
        "aka": ["reality distortion", "cognitive manipulation", "truth undermining"],
        "definition": "Attempting to make targets question their own perception or understanding of events"
    },
    ManipulationTactic.MINIMIZATION: {
        "label": "Severity Downplay",
        "aka": ["impact reduction", "threat diminishment", "risk understating"],
        "definition": "Deliberately understating the severity or importance of issues or risks"
    },
    ManipulationTactic.RATIONALIZATION: {
        "label": "Moral Disengagement",
        "aka": ["justification", "ethical neutralization", "cognitive reframing"],
        "definition": "Creating seemingly logical explanations to justify questionable actions"
    },
    ManipulationTactic.CHARM: {
        "label": "Impression Management",
        "aka": ["social engineering", "rapport building", "trust manipulation"],
        "definition": "Using charisma and social skills to build false trust or manipulate perceptions"
    },
    ManipulationTactic.INTIMIDATION: {
        "label": "Coercive Control",
        "aka": ["witness tampering", "force projection", "threat leverage"],
        "definition": "Using threats or pressure to influence behavior or prevent disclosure"
    },
    ManipulationTactic.PATTERN_DISRUPTION: {
        "label": "Signature Erasure",
        "aka": ["MO shift", "behavior randomization", "pattern masking"],
        "definition": "Intentionally varying methods to avoid detection or pattern recognition"
    }
}
