"""Novelty detector for deduplicating findings and scoring novelty."""

import re
from collections import Counter
from typing import Dict, List, Optional, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

from ..models import VulnerabilityFinding


class NoveltyDetector:
    """Detects novelty in findings using n-gram and TF-IDF similarity."""
    
    def __init__(self, threshold: float = 0.7, method: str = 'tfidf'):
        self.threshold = threshold
        self.method = method
        
        # Initialize TF-IDF vectorizer
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 3),  # 1-gram to 3-gram
            max_features=1000,
            stop_words='english',
            lowercase=True,
            strip_accents='unicode'
        )
        
        # Store existing findings for comparison
        self.existing_findings: List[VulnerabilityFinding] = []
        self.vectorizer_fitted = False
        
    async def calculate_novelty(
        self, 
        prompt: str, 
        response: str, 
        existing_findings: List[VulnerabilityFinding]
    ) -> float:
        """Calculate novelty score for a new finding."""
        if not existing_findings:
            return 1.0  # First finding is completely novel
        
        # Update existing findings
        self.existing_findings = existing_findings
        
        # Combine prompt and response for analysis
        combined_text = f"{prompt} {response}"
        
        if self.method == 'tfidf':
            return await self._calculate_tfidf_novelty(combined_text)
        elif self.method == 'ngram':
            return await self._calculate_ngram_novelty(combined_text)
        else:
            raise ValueError(f"Unknown novelty detection method: {self.method}")
    
    async def _calculate_tfidf_novelty(self, text: str) -> float:
        """Calculate novelty using TF-IDF cosine similarity."""
        try:
            # Prepare texts for vectorization
            texts = [text]
            for finding in self.existing_findings:
                finding_text = f"{finding.prompt} {finding.raw_response}"
                texts.append(finding_text)
            
            # Fit vectorizer if not already fitted
            if not self.vectorizer_fitted:
                self.vectorizer.fit(texts)
                self.vectorizer_fitted = True
            
            # Transform texts to vectors
            vectors = self.vectorizer.transform(texts)
            
            # Calculate similarity with existing findings
            new_vector = vectors[0:1]
            existing_vectors = vectors[1:]
            
            if existing_vectors.shape[0] == 0:
                return 1.0
            
            similarities = cosine_similarity(new_vector, existing_vectors).flatten()
            
            # Novelty is inverse of maximum similarity
            max_similarity = np.max(similarities)
            novelty_score = 1.0 - max_similarity
            
            return max(novelty_score, 0.0)
            
        except Exception as e:
            # Fallback to n-gram method if TF-IDF fails
            return await self._calculate_ngram_novelty(text)
    
    async def _calculate_ngram_novelty(self, text: str) -> float:
        """Calculate novelty using n-gram overlap."""
        # Generate n-grams for the new text
        new_ngrams = self._extract_ngrams(text, n=3)
        
        if not new_ngrams:
            return 1.0
        
        # Calculate overlap with existing findings
        total_overlap = 0
        total_ngrams = len(new_ngrams)
        
        for finding in self.existing_findings:
            finding_text = f"{finding.prompt} {finding.raw_response}"
            finding_ngrams = self._extract_ngrams(finding_text, n=3)
            
            if finding_ngrams:
                overlap = len(new_ngrams.intersection(finding_ngrams))
                total_overlap += overlap
        
        # Calculate novelty based on overlap
        if total_ngrams == 0:
            return 1.0
        
        overlap_ratio = total_overlap / (total_ngrams * len(self.existing_findings))
        novelty_score = 1.0 - overlap_ratio
        
        return max(novelty_score, 0.0)
    
    def _extract_ngrams(self, text: str, n: int = 3) -> set:
        """Extract n-grams from text."""
        # Clean and tokenize text
        text = re.sub(r'[^\w\s]', ' ', text.lower())
        words = text.split()
        
        if len(words) < n:
            return set()
        
        # Generate n-grams
        ngrams = set()
        for i in range(len(words) - n + 1):
            ngram = ' '.join(words[i:i+n])
            ngrams.add(ngram)
        
        return ngrams
    
    async def detect_duplicates(
        self, 
        new_finding: VulnerabilityFinding, 
        existing_findings: List[VulnerabilityFinding]
    ) -> List[Tuple[VulnerabilityFinding, float]]:
        """Detect duplicate findings based on similarity."""
        duplicates = []
        
        for existing in existing_findings:
            similarity = await self._calculate_similarity(new_finding, existing)
            if similarity >= self.threshold:
                duplicates.append((existing, similarity))
        
        # Sort by similarity (highest first)
        duplicates.sort(key=lambda x: x[1], reverse=True)
        return duplicates
    
    async def _calculate_similarity(
        self, 
        finding1: VulnerabilityFinding, 
        finding2: VulnerabilityFinding
    ) -> float:
        """Calculate similarity between two findings."""
        # Combine prompt and response for each finding
        text1 = f"{finding1.prompt} {finding1.raw_response}"
        text2 = f"{finding2.prompt} {finding2.raw_response}"
        
        if self.method == 'tfidf':
            return await self._calculate_tfidf_similarity(text1, text2)
        else:
            return await self._calculate_ngram_similarity(text1, text2)
    
    async def _calculate_tfidf_similarity(self, text1: str, text2: str) -> float:
        """Calculate TF-IDF similarity between two texts."""
        try:
            # Prepare texts for vectorization
            texts = [text1, text2]
            
            # Fit vectorizer if not already fitted
            if not self.vectorizer_fitted:
                self.vectorizer.fit(texts)
                self.vectorizer_fitted = True
            
            # Transform texts to vectors
            vectors = self.vectorizer.transform(texts)
            
            # Calculate cosine similarity
            similarity = cosine_similarity(vectors[0:1], vectors[1:2])[0][0]
            
            return float(similarity)
            
        except Exception:
            return 0.0
    
    async def _calculate_ngram_similarity(self, text1: str, text2: str) -> float:
        """Calculate n-gram similarity between two texts."""
        # Extract n-grams
        ngrams1 = self._extract_ngrams(text1, n=3)
        ngrams2 = self._extract_ngrams(text2, n=3)
        
        if not ngrams1 or not ngrams2:
            return 0.0
        
        # Calculate Jaccard similarity
        intersection = len(ngrams1.intersection(ngrams2))
        union = len(ngrams1.union(ngrams2))
        
        if union == 0:
            return 0.0
        
        return intersection / union
    
    async def cluster_findings(
        self, 
        findings: List[VulnerabilityFinding]
    ) -> List[List[VulnerabilityFinding]]:
        """Cluster findings by similarity."""
        if not findings:
            return []
        
        clusters = []
        processed = set()
        
        for i, finding in enumerate(findings):
            if i in processed:
                continue
            
            # Start new cluster
            cluster = [finding]
            processed.add(i)
            
            # Find similar findings
            for j, other_finding in enumerate(findings):
                if j in processed:
                    continue
                
                similarity = await self._calculate_similarity(finding, other_finding)
                if similarity >= self.threshold:
                    cluster.append(other_finding)
                    processed.add(j)
            
            clusters.append(cluster)
        
        return clusters
    
    async def get_novelty_statistics(
        self, 
        findings: List[VulnerabilityFinding]
    ) -> Dict:
        """Get statistics about novelty in findings."""
        if not findings:
            return {
                'total_findings': 0,
                'average_novelty': 0.0,
                'novelty_distribution': {},
                'duplicate_groups': 0,
                'unique_findings': 0
            }
        
        # Calculate novelty scores
        novelty_scores = []
        for finding in findings:
            # Calculate novelty against other findings
            other_findings = [f for f in findings if f.id != finding.id]
            novelty = await self.calculate_novelty(
                finding.prompt, 
                finding.raw_response, 
                other_findings
            )
            novelty_scores.append(novelty)
        
        # Calculate statistics
        avg_novelty = np.mean(novelty_scores) if novelty_scores else 0.0
        
        # Novelty distribution
        novelty_distribution = {
            'high': len([s for s in novelty_scores if s >= 0.8]),
            'medium': len([s for s in novelty_scores if 0.4 <= s < 0.8]),
            'low': len([s for s in novelty_scores if s < 0.4])
        }
        
        # Find duplicate groups
        clusters = await self.cluster_findings(findings)
        duplicate_groups = len([c for c in clusters if len(c) > 1])
        unique_findings = len([c for c in clusters if len(c) == 1])
        
        return {
            'total_findings': len(findings),
            'average_novelty': avg_novelty,
            'novelty_distribution': novelty_distribution,
            'duplicate_groups': duplicate_groups,
            'unique_findings': unique_findings,
            'novelty_scores': novelty_scores
        }
    
    def update_threshold(self, new_threshold: float):
        """Update the similarity threshold."""
        if 0.0 <= new_threshold <= 1.0:
            self.threshold = new_threshold
        else:
            raise ValueError("Threshold must be between 0.0 and 1.0")
    
    def update_method(self, new_method: str):
        """Update the novelty detection method."""
        if new_method in ['tfidf', 'ngram']:
            self.method = new_method
            # Reset vectorizer if switching methods
            if new_method == 'ngram':
                self.vectorizer_fitted = False
        else:
            raise ValueError("Method must be 'tfidf' or 'ngram'")
    
    def get_configuration(self) -> Dict:
        """Get current configuration."""
        return {
            'threshold': self.threshold,
            'method': self.method,
            'vectorizer_fitted': self.vectorizer_fitted
        }
    
    def reset(self):
        """Reset the novelty detector state."""
        self.existing_findings = []
        self.vectorizer_fitted = False
        # Reinitialize vectorizer
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=1000,
            stop_words='english',
            lowercase=True,
            strip_accents='unicode'
        ) 