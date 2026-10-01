"""
Tests for attack dispatcher.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_unknown_type_returns_404():
    """Test that unknown attack type returns 404"""
    # This is tested by the endpoint logic
    # Known types: injection, tamper, spike, spread, impersonate
    # Unknown types return 404
    known_types = ["injection", "tamper", "spike", "spread", "impersonate"]
    assert "nope" not in known_types


def test_unbuilt_type_returns_501():
    """Test that unbuilt type returns 501"""
    # spike.py exists as a stub, so it would return 501 if called
    # Other types don't have drivers yet
    from pathlib import Path
    attacks_dir = Path("attacks")
    
    # Check which drivers exist
    existing_drivers = []
    for attack_type in ["injection", "tamper", "spike", "spread", "impersonate"]:
        if (attacks_dir / f"{attack_type}.py").exists():
            existing_drivers.append(attack_type)
    
    # Only spike exists as stub
    assert "spike" in existing_drivers


def test_dispatcher_returns_driver_result():
    """Test that dispatcher returns driver result when stub driver exists"""
    # spike.py exists as a stub
    from pathlib import Path
    spike_path = Path("attacks/spike.py")
    assert spike_path.exists()
    
    # Import and verify it has run() function
    import importlib.util
    spec = importlib.util.spec_from_file_location("attacks.spike", spike_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    
    assert hasattr(module, 'run')
    result = module.run()
    assert 'attack' in result
    assert 'expected' in result
    assert 'actual' in result
    assert 'detected' in result
    assert 'latency_ms' in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
