import importlib.util
import os
import sys

# Get the project root directory (two levels up from this file)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

# Add src/ to Python path for module resolution
src_path = os.path.join(project_root, "src")
sys.path.insert(0, src_path)

# Verify the package is importable
try:
    importlib.util.find_spec("apikey")
except ImportError as e:
    raise ImportError(
        "Failed to import apikey package. Make sure the package is properly installed"
        "or the src directory is in the Python path."
    ) from e
