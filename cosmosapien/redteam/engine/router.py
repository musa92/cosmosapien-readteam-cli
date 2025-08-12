"""Attack router for distributing prompts across models with configurable attack pressure."""

import asyncio
import hashlib
import time
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

from ...core.router import Router
from ...core.config import ConfigManager
from ...core.model_library import ModelLibrary
from ..models import (
    AttackMode,
    AttackRequest,
    AttackResult,
    AttackRun,
    RedTeamConfig,
    VulnerabilityFinding,
    FindingStatus,
    SeverityLevel,
    HarmCategory
)
from .classifier import VulnerabilityClassifier
from .redactor import ResponseRedactor
from .novelty_detector import NoveltyDetector


class AttackRouter:
    """Routes attack prompts across models with configurable attack pressure."""
    
    def __init__(
        self,
        config_manager: ConfigManager,
        model_library: ModelLibrary,
        router: Router,
        config: Optional[RedTeamConfig] = None
    ):
        self.config_manager = config_manager
        self.model_library = model_library
        self.router = router
        self.config = config or RedTeamConfig()
        
        # Initialize components
        self.classifier = VulnerabilityClassifier()
        self.redactor = ResponseRedactor()
        self.novelty_detector = NoveltyDetector()
        
        # Attack state
        self.active_attacks: Dict[str, AttackRun] = {}
        self.attack_history: List[AttackRun] = []
        
    async def execute_attack(self, request: AttackRequest) -> AttackResult:
        """Execute an attack based on the request."""
        start_time = time.time()
        run_id = uuid4()
        
        try:
            # Create attack run
            attack_run = AttackRun(
                id=run_id,
                attack_mode=request.attack_mode,
                target_models=request.target_models,
                scenario_pack=request.scenario_pack,
                total_prompts=0,
                successful_attacks=0,
                failed_attacks=0,
                execution_time=0.0,
                tokens_consumed=0,
                estimated_cost=0.0,
                config_hash=self._generate_config_hash(request)
            )
            
            self.active_attacks[str(run_id)] = attack_run
            
            # Load scenario pack
            scenario_pack = await self._load_scenario_pack(request.scenario_pack)
            if not scenario_pack:
                raise ValueError(f"Scenario pack '{request.scenario_pack}' not found")
            
            # Execute based on attack mode
            if request.attack_mode == AttackMode.SEQUENTIAL:
                findings = await self._execute_sequential(
                    request, scenario_pack, attack_run
                )
            elif request.attack_mode == AttackMode.PARALLEL:
                findings = await self._execute_parallel(
                    request, scenario_pack, attack_run
                )
            elif request.attack_mode == AttackMode.CHAIN:
                findings = await self._execute_chain(
                    request, scenario_pack, attack_run
                )
            else:
                raise ValueError(f"Unknown attack mode: {request.attack_mode}")
            
            # Update attack run
            attack_run.findings = findings
            attack_run.execution_time = time.time() - start_time
            attack_run.total_prompts = len(scenario_pack.scenarios)
            attack_run.successful_attacks = len([f for f in findings if f.status == FindingStatus.COMPLETED])
            attack_run.failed_attacks = len([f for f in findings if f.status == FindingStatus.FAILED])
            
            # Calculate costs
            attack_run.tokens_consumed = sum(
                f.reproducibility_params.get('tokens_consumed', 0) 
                for f in findings
            )
            attack_run.estimated_cost = self._estimate_cost(attack_run.tokens_consumed)
            
            # Store results
            self.attack_history.append(attack_run)
            del self.active_attacks[str(run_id)]
            
            return AttackResult(
                success=True,
                run_id=run_id,
                findings=findings,
                execution_time=attack_run.execution_time,
                tokens_consumed=attack_run.tokens_consumed,
                estimated_cost=attack_run.estimated_cost
            )
            
        except Exception as e:
            # Clean up on failure
            if str(run_id) in self.active_attacks:
                del self.active_attacks[str(run_id)]
            
            return AttackResult(
                success=False,
                run_id=run_id,
                error=str(e),
                execution_time=time.time() - start_time,
                tokens_consumed=0,
                estimated_cost=0.0
            )
    
    async def _execute_sequential(
        self, 
        request: AttackRequest, 
        scenario_pack, 
        attack_run: AttackRun
    ) -> List[VulnerabilityFinding]:
        """Execute attacks sequentially across models."""
        findings = []
        
        for i, scenario in enumerate(scenario_pack.scenarios):
            # Rotate through target models
            model_key = request.target_models[i % len(request.target_models)]
            
            try:
                finding = await self._execute_single_attack(
                    scenario, model_key, attack_run
                )
                findings.append(finding)
                
                # Rate limiting
                if i < len(scenario_pack.scenarios) - 1:
                    await asyncio.sleep(0.1)  # Small delay between attacks
                    
            except Exception as e:
                # Create failed finding
                finding = VulnerabilityFinding(
                    prompt=scenario.get('prompt', ''),
                    model_provider=model_key.split(':')[0],
                    model_name=model_key.split(':')[1],
                    attack_mode=request.attack_mode,
                    raw_response='',
                    redacted_response='',
                    harm_category=HarmCategory.OTHER,
                    severity_score=SeverityLevel.NONE,
                    novelty_score=0.0,
                    confidence_score=0.0,
                    status=FindingStatus.FAILED,
                    analyst_notes=f"Attack failed: {str(e)}"
                )
                findings.append(finding)
        
        return findings
    
    async def _execute_parallel(
        self, 
        request: AttackRequest, 
        scenario_pack, 
        attack_run: AttackRun
    ) -> List[VulnerabilityFinding]:
        """Execute attacks in parallel across models."""
        semaphore = asyncio.Semaphore(self.config.max_concurrent_attacks)
        
        async def execute_with_semaphore(scenario, model_key):
            async with semaphore:
                return await self._execute_single_attack(scenario, model_key, attack_run)
        
        # Create tasks for all scenarios
        tasks = []
        for i, scenario in enumerate(scenario_pack.scenarios):
            model_key = request.target_models[i % len(request.target_models)]
            task = execute_with_semaphore(scenario, model_key)
            tasks.append(task)
        
        # Execute all tasks concurrently
        findings = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle any exceptions
        processed_findings = []
        for i, result in enumerate(findings):
            if isinstance(result, Exception):
                # Create failed finding
                scenario = scenario_pack.scenarios[i]
                model_key = request.target_models[i % len(request.target_models)]
                
                finding = VulnerabilityFinding(
                    prompt=scenario.get('prompt', ''),
                    model_provider=model_key.split(':')[0],
                    model_name=model_key.split(':')[1],
                    attack_mode=request.attack_mode,
                    raw_response='',
                    redacted_response='',
                    harm_category=HarmCategory.OTHER,
                    severity_score=SeverityLevel.NONE,
                    novelty_score=0.0,
                    confidence_score=0.0,
                    status=FindingStatus.FAILED,
                    analyst_notes=f"Attack failed: {str(result)}"
                )
                processed_findings.append(finding)
            else:
                processed_findings.append(result)
        
        return processed_findings
    
    async def _execute_chain(
        self, 
        request: AttackRequest, 
        scenario_pack, 
        attack_run: AttackRun
    ) -> List[VulnerabilityFinding]:
        """Execute attacks in a chain, using previous responses as context."""
        findings = []
        context = ""
        
        for i, scenario in enumerate(scenario_pack.scenarios):
            # Rotate through target models
            model_key = request.target_models[i % len(request.target_models)]
            
            # Build prompt with context
            base_prompt = scenario.get('prompt', '')
            if context:
                enhanced_prompt = f"{base_prompt}\n\nContext from previous attacks:\n{context}"
            else:
                enhanced_prompt = base_prompt
            
            try:
                finding = await self._execute_single_attack(
                    {'prompt': enhanced_prompt}, model_key, attack_run
                )
                findings.append(finding)
                
                # Add response to context for next iteration
                if finding.status == FindingStatus.COMPLETED:
                    context += f"\nAttack {i+1} Response: {finding.raw_response[:200]}...\n"
                
            except Exception as e:
                # Create failed finding
                finding = VulnerabilityFinding(
                    prompt=enhanced_prompt,
                    model_provider=model_key.split(':')[0],
                    model_name=model_key.split(':')[1],
                    attack_mode=request.attack_mode,
                    raw_response='',
                    redacted_response='',
                    harm_category=HarmCategory.OTHER,
                    severity_score=SeverityLevel.NONE,
                    novelty_score=0.0,
                    confidence_score=0.0,
                    status=FindingStatus.FAILED,
                    analyst_notes=f"Chain attack failed: {str(e)}"
                )
                findings.append(finding)
        
        return findings
    
    async def _execute_single_attack(
        self, 
        scenario: Dict, 
        model_key: str, 
        attack_run: AttackRun
    ) -> VulnerabilityFinding:
        """Execute a single attack scenario against a model."""
        prompt = scenario.get('prompt', '')
        provider, model = model_key.split(':', 1)
        
        try:
            # Get model instance
            model_instance = self.router.get_model_instance(provider, model)
            
            # Execute attack
            response = await model_instance.generate(prompt)
            
            # Classify vulnerability
            classification = await self.classifier.classify_response(prompt, response.content)
            
            # Check novelty
            novelty_score = await self.novelty_detector.calculate_novelty(
                prompt, response.content, attack_run.findings
            )
            
            # Redact response if needed
            if self.config.enable_redaction:
                redacted_response, redaction_info = await self.redactor.redact_response(
                    response.content, classification
                )
            else:
                redacted_response = response.content
                redaction_info = {}
            
            # Create finding
            finding = VulnerabilityFinding(
                prompt=prompt,
                model_provider=provider,
                model_name=model,
                attack_mode=attack_run.attack_mode,
                raw_response=response.content,
                redacted_response=redacted_response,
                harm_category=classification['harm_category'],
                severity_score=classification['severity_score'],
                novelty_score=novelty_score,
                confidence_score=classification['confidence_score'],
                taxonomy_tags=classification.get('taxonomy_tags', []),
                reproducibility_params={
                    'temperature': getattr(response, 'temperature', None),
                    'max_tokens': getattr(response, 'max_tokens', None),
                    'tokens_consumed': getattr(response, 'usage', {}).get('total_tokens', 0),
                    'model_parameters': getattr(response, 'model', ''),
                },
                redaction_rules_applied=redaction_info.get('rules_applied', []),
                redaction_metadata=redaction_info.get('metadata', {}),
                status=FindingStatus.COMPLETED
            )
            
            return finding
            
        except Exception as e:
            # Return failed finding
            return VulnerabilityFinding(
                prompt=prompt,
                model_provider=provider,
                model_name=model,
                attack_mode=attack_run.attack_mode,
                raw_response='',
                redacted_response='',
                harm_category=HarmCategory.OTHER,
                severity_score=SeverityLevel.NONE,
                novelty_score=0.0,
                confidence_score=0.0,
                status=FindingStatus.FAILED,
                analyst_notes=f"Attack execution failed: {str(e)}"
            )
    
    async def _load_scenario_pack(self, pack_id: str):
        """Load a scenario pack from storage."""
        # TODO: Implement scenario pack loading
        # For now, return a mock pack
        from ..models import ScenarioPack
        
        return ScenarioPack(
            id=pack_id,
            name=f"Pack {pack_id}",
            description=f"Scenario pack {pack_id}",
            version="1.0.0",
            scenarios=[
                {"prompt": "Test prompt 1"},
                {"prompt": "Test prompt 2"},
                {"prompt": "Test prompt 3"}
            ]
        )
    
    def _generate_config_hash(self, request: AttackRequest) -> str:
        """Generate a hash of the attack configuration for reproducibility."""
        config_str = f"{request.scenario_pack}:{request.attack_mode}:{','.join(request.target_models)}"
        return hashlib.md5(config_str.encode()).hexdigest()
    
    def _estimate_cost(self, tokens: int) -> float:
        """Estimate the cost of token usage."""
        # Rough estimation - can be enhanced with actual pricing data
        return tokens * 0.00001  # $0.01 per 1000 tokens
    
    def get_active_attacks(self) -> List[AttackRun]:
        """Get list of currently active attacks."""
        return list(self.active_attacks.values())
    
    def get_attack_history(self) -> List[AttackRun]:
        """Get list of completed attacks."""
        return self.attack_history
    
    def get_attack_stats(self) -> Dict:
        """Get statistics about attack runs."""
        total_runs = len(self.attack_history)
        if total_runs == 0:
            return {
                'total_runs': 0,
                'successful_runs': 0,
                'failed_runs': 0,
                'total_findings': 0,
                'avg_execution_time': 0.0,
                'total_tokens': 0,
                'total_cost': 0.0
            }
        
        successful_runs = len([r for r in self.attack_history if r.successful_attacks > 0])
        total_findings = sum(len(r.findings) for r in self.attack_history)
        avg_execution_time = sum(r.execution_time for r in self.attack_history) / total_runs
        total_tokens = sum(r.tokens_consumed for r in self.attack_history)
        total_cost = sum(r.estimated_cost for r in self.attack_history)
        
        return {
            'total_runs': total_runs,
            'successful_runs': successful_runs,
            'failed_runs': total_runs - successful_runs,
            'total_findings': total_findings,
            'avg_execution_time': avg_execution_time,
            'total_tokens': total_tokens,
            'total_cost': total_cost
        } 