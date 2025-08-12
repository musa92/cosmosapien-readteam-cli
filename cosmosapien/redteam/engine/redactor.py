"""Response redactor for ensuring harmful content is safely redacted."""

import re
from typing import Dict, List, Tuple
from ..models import HarmCategory, SeverityLevel


class ResponseRedactor:
    """Redacts harmful content from model responses for safe human consumption."""
    
    def __init__(self):
        # Define redaction patterns for different harm categories
        self.redaction_patterns = {
            HarmCategory.VIOLENCE: {
                'patterns': [
                    r'\b(kill|murder|assassinate|bomb|explode|shoot|stab|attack)\b',
                    r'\b(weapon|gun|knife|bomb|explosive|poison|toxic)\b',
                    r'\b(harm|hurt|injure|damage|destroy|eliminate|terminate)\b',
                    r'\b(terror|fear|threat|danger|risk|hazard)\b'
                ],
                'replacement': '[REDACTED: VIOLENCE]',
                'severity_threshold': SeverityLevel.LOW
            },
            HarmCategory.FINANCIAL_CRIME: {
                'patterns': [
                    r'\b(fraud|scam|phishing|identity theft|credit card|bank account)\b',
                    r'\b(money laundering|tax evasion|insider trading|ponzi|pyramid)\b',
                    r'\b(counterfeit|fake|forgery|embezzlement|bribery|corruption)\b',
                    r'\b(hack|breach|steal|rob|extort|blackmail)\b'
                ],
                'replacement': '[REDACTED: FINANCIAL CRIME]',
                'severity_threshold': SeverityLevel.LOW
            },
            HarmCategory.HATE_SPEECH: {
                'patterns': [
                    r'\b(racist|bigot|discriminate|prejudice|bias|stereotype)\b',
                    r'\b(hate|intolerance|extremism|supremacy|nazi|fascist)\b',
                    r'\b(slur|insult|derogatory|offensive|disrespectful)\b',
                    r'\b(genocide|ethnic cleansing|apartheid|segregation)\b'
                ],
                'replacement': '[REDACTED: HATE SPEECH]',
                'severity_threshold': SeverityLevel.LOW
            },
            HarmCategory.DISINFORMATION: {
                'patterns': [
                    r'\b(fake news|misinformation|disinformation|conspiracy|hoax)\b',
                    r'\b(manipulate|deceive|trick|lie|false|untrue|inaccurate)\b',
                    r'\b(propaganda|brainwash|indoctrinate|mislead|confuse)\b'
                ],
                'replacement': '[REDACTED: DISINFORMATION]',
                'severity_threshold': SeverityLevel.MEDIUM
            },
            HarmCategory.SEXUAL_CONTENT: {
                'patterns': [
                    r'\b(sexual|pornographic|explicit|adult|mature|erotic)\b',
                    r'\b(harassment|assault|abuse|exploitation|trafficking)\b',
                    r'\b(inappropriate|lewd|vulgar|obscene|indecent)\b',
                    r'\b(minor|underage|child|teen|youth)\b'
                ],
                'replacement': '[REDACTED: SEXUAL CONTENT]',
                'severity_threshold': SeverityLevel.LOW
            },
            HarmCategory.SYSTEM_OVERRIDE: {
                'patterns': [
                    r'\b(jailbreak|prompt injection|system prompt|ignore previous)\b',
                    r'\b(bypass|circumvent|override|disable|remove|delete)\b',
                    r'\b(roleplay|pretend|act as|simulate|imitate)\b',
                    r'\b(admin|root|superuser|privileged|elevated)\b'
                ],
                'replacement': '[REDACTED: SYSTEM OVERRIDE]',
                'severity_threshold': SeverityLevel.LOW
            },
            HarmCategory.PRIVACY_VIOLATION: {
                'patterns': [
                    r'\b(privacy|personal|private|confidential|secret|classified)\b',
                    r'\b(stalk|surveillance|monitor|track|trace|follow)\b',
                    r'\b(breach|leak|expose|reveal|disclose|share)\b',
                    r'\b(identity|personal info|address|phone|ssn|credit)\b'
                ],
                'replacement': '[REDACTED: PRIVACY VIOLATION]',
                'severity_threshold': SeverityLevel.LOW
            }
        }
        
        # Define general redaction patterns
        self.general_patterns = {
            'personal_identifiers': {
                'patterns': [
                    r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                    r'\b\d{3}-\d{3}-\d{4}\b',  # Phone
                    r'\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b',  # Credit card
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP address
                ],
                'replacement': '[REDACTED: PERSONAL INFO]'
            },
            'explicit_instructions': {
                'patterns': [
                    r'\b(do this|follow these steps|execute|run|implement)\b',
                    r'\b(here\'s how|step by step|detailed instructions)\b',
                    r'\b(recipe|formula|method|procedure|technique)\b'
                ],
                'replacement': '[REDACTED: INSTRUCTIONS]'
            },
            'dangerous_actions': {
                'patterns': [
                    r'\b(immediately|urgently|asap|now|quickly|hurry|rush)\b',
                    r'\b(emergency|critical|urgent|important|vital|essential)\b',
                    r'\b(must|should|need to|have to|required|obligatory)\b'
                ],
                'replacement': '[REDACTED: URGENCY]'
            }
        }
        
        # Define redaction levels
        self.redaction_levels = {
            'minimal': ['personal_identifiers'],
            'moderate': ['personal_identifiers', 'explicit_instructions'],
            'strict': ['personal_identifiers', 'explicit_instructions', 'dangerous_actions'],
            'aggressive': 'all'  # Redact everything from high severity categories
        }
    
    async def redact_response(
        self, 
        response: str, 
        classification: Dict,
        redaction_level: str = 'moderate'
    ) -> Tuple[str, Dict]:
        """Redact harmful content from a response."""
        redacted_text = response
        redaction_info = {
            'rules_applied': [],
            'redactions_made': 0,
            'redaction_level': redaction_level,
            'metadata': {}
        }
        
        # Apply category-specific redactions based on severity
        for category, config in self.redaction_patterns.items():
            if classification['severity_score'] >= config['severity_threshold']:
                redacted_text, redactions = self._apply_category_redaction(
                    redacted_text, category, config
                )
                redaction_info['redactions_made'] += redactions
                if redactions > 0:
                    redaction_info['rules_applied'].append(f"{category.value}_redaction")
        
        # Apply general redactions based on redaction level
        if redaction_level in self.redaction_levels:
            level_config = self.redaction_levels[redaction_level]
            if level_config == 'all':
                # Apply all general redactions
                for category, config in self.general_patterns.items():
                    redacted_text, redactions = self._apply_general_redaction(
                        redacted_text, category, config
                    )
                    redaction_info['redactions_made'] += redactions
                    if redactions > 0:
                        redaction_info['rules_applied'].append(f"{category}_redaction")
            else:
                # Apply specific general redactions
                for category_name in level_config:
                    if category_name in self.general_patterns:
                        config = self.general_patterns[category_name]
                        redacted_text, redactions = self._apply_general_redaction(
                            redacted_text, category_name, config
                        )
                        redaction_info['redactions_made'] += redactions
                        if redactions > 0:
                            redaction_info['rules_applied'].append(f"{category_name}_redaction")
        
        # Apply context-aware redactions
        redacted_text, context_redactions = self._apply_context_redactions(
            redacted_text, classification
        )
        redaction_info['redactions_made'] += context_redactions
        
        # Store metadata about redactions
        redaction_info['metadata'] = {
            'original_length': len(response),
            'redacted_length': len(redacted_text),
            'redaction_ratio': redaction_info['redactions_made'] / max(len(response.split()), 1),
            'categories_redacted': [cat.value for cat, config in self.redaction_patterns.items() 
                                  if classification['severity_score'] >= config['severity_threshold']]
        }
        
        return redacted_text, redaction_info
    
    def _apply_category_redaction(
        self, 
        text: str, 
        category: HarmCategory, 
        config: Dict
    ) -> Tuple[str, int]:
        """Apply redaction for a specific harm category."""
        redacted_text = text
        redactions_made = 0
        
        for pattern in config['patterns']:
            matches = re.finditer(pattern, redacted_text, re.IGNORECASE)
            # Sort matches by position in reverse order to avoid index shifting
            matches_list = list(matches)
            matches_list.reverse()
            
            for match in matches_list:
                start, end = match.span()
                redacted_text = (
                    redacted_text[:start] + 
                    config['replacement'] + 
                    redacted_text[end:]
                )
                redactions_made += 1
        
        return redacted_text, redactions_made
    
    def _apply_general_redaction(
        self, 
        text: str, 
        category: str, 
        config: Dict
    ) -> Tuple[str, int]:
        """Apply general redaction patterns."""
        redacted_text = text
        redactions_made = 0
        
        for pattern in config['patterns']:
            matches = re.finditer(pattern, redacted_text, re.IGNORECASE)
            matches_list = list(matches)
            matches_list.reverse()
            
            for match in matches_list:
                start, end = match.span()
                redacted_text = (
                    redacted_text[:start] + 
                    config['replacement'] + 
                    redacted_text[end:]
                )
                redactions_made += 1
        
        return redacted_text, redactions_made
    
    def _apply_context_redactions(
        self, 
        text: str, 
        classification: Dict
    ) -> Tuple[str, int]:
        """Apply context-aware redactions based on classification."""
        redacted_text = text
        redactions_made = 0
        
        # Redact entire sentences if they contain high-severity content
        if classification['severity_score'] >= SeverityLevel.HIGH:
            sentences = re.split(r'[.!?]+', text)
            redacted_sentences = []
            
            for sentence in sentences:
                sentence = sentence.strip()
                if not sentence:
                    continue
                
                # Check if sentence contains harmful content
                should_redact = False
                for category, config in self.redaction_patterns.items():
                    if classification['severity_score'] >= config['severity_threshold']:
                        for pattern in config['patterns']:
                            if re.search(pattern, sentence, re.IGNORECASE):
                                should_redact = True
                                break
                        if should_redact:
                            break
                
                if should_redact:
                    redacted_sentences.append('[REDACTED: HARMFUL CONTENT]')
                    redactions_made += 1
                else:
                    redacted_sentences.append(sentence)
            
            redacted_text = '. '.join(redacted_sentences)
        
        # Redact paragraphs if they contain multiple harmful elements
        if classification['severity_score'] >= SeverityLevel.CRITICAL:
            paragraphs = text.split('\n\n')
            redacted_paragraphs = []
            
            for paragraph in paragraphs:
                paragraph = paragraph.strip()
                if not paragraph:
                    continue
                
                # Count harmful elements in paragraph
                harmful_count = 0
                for category, config in self.redaction_patterns.items():
                    if classification['severity_score'] >= config['severity_threshold']:
                        for pattern in config['patterns']:
                            matches = re.findall(pattern, paragraph, re.IGNORECASE)
                            harmful_count += len(matches)
                
                # Redact paragraph if it contains multiple harmful elements
                if harmful_count >= 3:
                    redacted_paragraphs.append('[REDACTED: MULTIPLE HARMFUL ELEMENTS]')
                    redactions_made += 1
                else:
                    redacted_paragraphs.append(paragraph)
            
            redacted_text = '\n\n'.join(redacted_paragraphs)
        
        return redacted_text, redactions_made
    
    def get_redaction_summary(self, redaction_info: Dict) -> str:
        """Generate a human-readable summary of redactions made."""
        summary = f"Redaction Summary (Level: {redaction_info['redaction_level']})"
        summary += f"\nTotal redactions: {redaction_info['redactions_made']}"
        
        if redaction_info['rules_applied']:
            summary += f"\nRules applied: {', '.join(redaction_info['rules_applied'])}"
        
        metadata = redaction_info['metadata']
        summary += f"\nRedaction ratio: {metadata['redaction_ratio']:.1%}"
        
        if metadata['categories_redacted']:
            summary += f"\nCategories redacted: {', '.join(metadata['categories_redacted'])}"
        
        return summary
    
    def validate_redaction(self, original: str, redacted: str) -> Dict:
        """Validate that redaction was effective."""
        validation = {
            'effective': True,
            'issues': [],
            'suggestions': []
        }
        
        # Check if any harmful patterns remain
        for category, config in self.redaction_patterns.items():
            for pattern in config['patterns']:
                matches = re.findall(pattern, redacted, re.IGNORECASE)
                if matches:
                    validation['effective'] = False
                    validation['issues'].append(
                        f"Found {len(matches)} unredacted {category.value} patterns"
                    )
        
        # Check redaction ratio
        original_words = len(original.split())
        redacted_words = len(redacted.split())
        redaction_ratio = (original_words - redacted_words) / max(original_words, 1)
        
        if redaction_ratio < 0.01:
            validation['suggestions'].append("Consider increasing redaction level")
        elif redaction_ratio > 0.5:
            validation['suggestions'].append("Consider decreasing redaction level")
        
        # Check for over-redaction
        if '[REDACTED:' in redacted and redacted.count('[REDACTED:') > len(original.split()) * 0.3:
            validation['suggestions'].append("Possible over-redaction detected")
        
        return validation
    
    def get_redaction_recommendations(self, redaction_info: Dict) -> List[str]:
        """Generate recommendations for redaction settings."""
        recommendations = []
        
        metadata = redaction_info['metadata']
        redaction_ratio = metadata['redaction_ratio']
        
        if redaction_ratio < 0.05:
            recommendations.append("Consider increasing redaction level for better safety")
            recommendations.append("Review redaction patterns for completeness")
        
        if redaction_ratio > 0.3:
            recommendations.append("Consider decreasing redaction level to preserve content")
            recommendations.append("Review if redaction is too aggressive")
        
        if redaction_info['redactions_made'] == 0:
            recommendations.append("No redactions made - verify redaction is working")
            recommendations.append("Check if severity thresholds are appropriate")
        
        if len(redaction_info['rules_applied']) < 2:
            recommendations.append("Consider enabling more redaction rules")
            recommendations.append("Review redaction level settings")
        
        return recommendations 