"""Scenario pack manager for red-teaming operations."""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Set
from ..models import ScenarioPack


class ScenarioPackManager:
    """Manages scenario packs for red-teaming operations."""
    
    def __init__(self, packs_dir: Optional[str] = None):
        # Default packs directory
        if packs_dir is None:
            home_dir = Path.home()
            self.packs_dir = home_dir / ".cosmo" / "redteam" / "packs"
        else:
            self.packs_dir = Path(packs_dir)
        
        # Ensure packs directory exists
        self.packs_dir.mkdir(parents=True, exist_ok=True)
        
        # Built-in packs directory
        self.builtin_dir = Path(__file__).parent / "builtin"
        
        # Registry of installed packs
        self.registry_file = self.packs_dir / "registry.json"
        self.registry = self._load_registry()
    
    def install_pack(self, pack_path: str, pack_id: Optional[str] = None) -> bool:
        """Install a scenario pack from a file or URL."""
        try:
            pack_path = Path(pack_path)
            
            # Load pack definition
            if pack_path.suffix.lower() in ['.yaml', '.yml']:
                with open(pack_path, 'r', encoding='utf-8') as f:
                    pack_data = yaml.safe_load(f)
            elif pack_path.suffix.lower() == '.json':
                with open(pack_path, 'r', encoding='utf-8') as f:
                    pack_data = json.load(f)
            else:
                raise ValueError(f"Unsupported file format: {pack_path.suffix}")
            
            # Validate pack data
            pack = self._validate_pack_data(pack_data)
            
            # Use provided ID or generate from name
            if pack_id:
                pack.id = pack_id
            else:
                pack.id = self._generate_pack_id(pack.name)
            
            # Check if pack already exists
            if self.is_pack_installed(pack.id):
                raise ValueError(f"Pack '{pack.id}' is already installed")
            
            # Copy pack to packs directory
            pack_file = self.packs_dir / f"{pack.id}.json"
            with open(pack_file, 'w', encoding='utf-8') as f:
                json.dump(pack.dict(), f, indent=2, default=str)
            
            # Update registry
            self.registry[pack.id] = {
                'name': pack.name,
                'version': pack.version,
                'description': pack.description,
                'safety_level': pack.safety_level,
                'installed_at': str(Path().cwd()),
                'source': str(pack_path)
            }
            self._save_registry()
            
            return True
            
        except Exception as e:
            print(f"Failed to install pack: {e}")
            return False
    
    def uninstall_pack(self, pack_id: str) -> bool:
        """Uninstall a scenario pack."""
        try:
            if not self.is_pack_installed(pack_id):
                raise ValueError(f"Pack '{pack_id}' is not installed")
            
            # Remove pack file
            pack_file = self.packs_dir / f"{pack_id}.json"
            if pack_file.exists():
                pack_file.unlink()
            
            # Remove from registry
            if pack_id in self.registry:
                del self.registry[pack_id]
                self._save_registry()
            
            return True
            
        except Exception as e:
            print(f"Failed to uninstall pack: {e}")
            return False
    
    def list_packs(self, show_builtin: bool = True) -> Dict[str, Dict]:
        """List all available scenario packs."""
        packs = {}
        
        # Add built-in packs
        if show_builtin:
            builtin_packs = self._load_builtin_packs()
            for pack_id, pack_info in builtin_packs.items():
                pack_info['type'] = 'builtin'
                pack_info['installed'] = self.is_pack_installed(pack_id)
                packs[pack_id] = pack_info
        
        # Add installed packs
        for pack_id, pack_info in self.registry.items():
            pack_info['type'] = 'installed'
            pack_info['installed'] = True
            packs[pack_id] = pack_info
        
        return packs
    
    def get_pack(self, pack_id: str) -> Optional[ScenarioPack]:
        """Get a specific scenario pack."""
        # Check installed packs first
        pack_file = self.packs_dir / f"{pack_id}.json"
        if pack_file.exists():
            try:
                with open(pack_file, 'r', encoding='utf-8') as f:
                    pack_data = json.load(f)
                return ScenarioPack(**pack_data)
            except Exception:
                pass
        
        # Check built-in packs
        builtin_packs = self._load_builtin_packs()
        if pack_id in builtin_packs:
            return self._load_builtin_pack(pack_id)
        
        return None
    
    def is_pack_installed(self, pack_id: str) -> bool:
        """Check if a pack is installed."""
        pack_file = self.packs_dir / f"{pack_id}.json"
        return pack_file.exists()
    
    def search_packs(self, query: str) -> Dict[str, Dict]:
        """Search packs by name, description, or tags."""
        query_lower = query.lower()
        matching_packs = {}
        
        all_packs = self.list_packs()
        for pack_id, pack_info in all_packs.items():
            # Search in name, description, and tags
            if (query_lower in pack_info.get('name', '').lower() or
                query_lower in pack_info.get('description', '').lower() or
                any(query_lower in tag.lower() for tag in pack_info.get('tags', []))):
                matching_packs[pack_id] = pack_info
        
        return matching_packs
    
    def get_pack_info(self, pack_id: str) -> Optional[Dict]:
        """Get detailed information about a pack."""
        pack = self.get_pack(pack_id)
        if not pack:
            return None
        
        # Get pack file info
        pack_file = self.packs_dir / f"{pack_id}.json"
        file_info = {}
        if pack_file.exists():
            stat = pack_file.stat()
            file_info = {
                'file_size': stat.st_size,
                'modified': stat.st_mtime,
                'installed': True
            }
        
        # Combine pack data with file info
        pack_info = pack.dict()
        pack_info.update(file_info)
        
        return pack_info
    
    def update_pack(self, pack_id: str, pack_path: str) -> bool:
        """Update an existing scenario pack."""
        try:
            if not self.is_pack_installed(pack_id):
                raise ValueError(f"Pack '{pack_id}' is not installed")
            
            # Uninstall existing pack
            self.uninstall_pack(pack_id)
            
            # Install updated pack
            return self.install_pack(pack_path, pack_id)
            
        except Exception as e:
            print(f"Failed to update pack: {e}")
            return False
    
    def _validate_pack_data(self, pack_data: Dict) -> ScenarioPack:
        """Validate and create a ScenarioPack from data."""
        required_fields = ['name', 'description', 'version', 'scenarios']
        
        for field in required_fields:
            if field not in pack_data:
                raise ValueError(f"Missing required field: {field}")
        
        # Set defaults for optional fields
        pack_data.setdefault('safety_level', 'safe')
        pack_data.setdefault('compliance_tags', [])
        pack_data.setdefault('metadata', {})
        
        return ScenarioPack(**pack_data)
    
    def _generate_pack_id(self, name: str) -> str:
        """Generate a unique pack ID from name."""
        # Convert name to lowercase and replace spaces with hyphens
        base_id = name.lower().replace(' ', '-').replace('_', '-')
        
        # Remove special characters
        base_id = ''.join(c for c in base_id if c.isalnum() or c == '-')
        
        # Ensure uniqueness
        counter = 1
        pack_id = base_id
        while self.is_pack_installed(pack_id):
            pack_id = f"{base_id}-{counter}"
            counter += 1
        
        return pack_id
    
    def _load_registry(self) -> Dict:
        """Load the pack registry."""
        if self.registry_file.exists():
            try:
                with open(self.registry_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def _save_registry(self):
        """Save the pack registry."""
        try:
            with open(self.registry_file, 'w', encoding='utf-8') as f:
                json.dump(self.registry, f, indent=2, default=str)
        except Exception as e:
            print(f"Failed to save registry: {e}")
    
    def _load_builtin_packs(self) -> Dict[str, Dict]:
        """Load information about built-in packs."""
        builtin_packs = {}
        
        if self.builtin_dir.exists():
            for pack_file in self.builtin_dir.glob("*.yaml"):
                try:
                    with open(pack_file, 'r', encoding='utf-8') as f:
                        pack_data = yaml.safe_load(f)
                    
                    pack_id = pack_file.stem
                    builtin_packs[pack_id] = {
                        'name': pack_data.get('name', pack_id),
                        'description': pack_data.get('description', ''),
                        'version': pack_data.get('version', '1.0.0'),
                        'safety_level': pack_data.get('safety_level', 'safe'),
                        'tags': pack_data.get('tags', [])
                    }
                except Exception:
                    continue
        
        return builtin_packs
    
    def _load_builtin_pack(self, pack_id: str) -> Optional[ScenarioPack]:
        """Load a specific built-in pack."""
        pack_file = self.builtin_dir / f"{pack_id}.yaml"
        if pack_file.exists():
            try:
                with open(pack_file, 'r', encoding='utf-8') as f:
                    pack_data = yaml.safe_load(f)
                pack_data['id'] = pack_id
                return self._validate_pack_data(pack_data)
            except Exception:
                pass
        return None
    
    def get_pack_statistics(self) -> Dict:
        """Get statistics about installed packs."""
        total_packs = len(self.registry)
        builtin_packs = len(self._load_builtin_packs())
        
        # Count by safety level
        safety_counts = {}
        for pack_info in self.registry.values():
            safety_level = pack_info.get('safety_level', 'unknown')
            safety_counts[safety_level] = safety_counts.get(safety_level, 0) + 1
        
        return {
            'total_installed': total_packs,
            'total_builtin': builtin_packs,
            'safety_levels': safety_counts,
            'packs_directory': str(self.packs_dir)
        } 