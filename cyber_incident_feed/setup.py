"""
Setup script for Cyber Incident Feed Generator
"""
import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e.stderr}")
        return False

def setup_project():
    """Setup the entire project"""
    print("🔒 Cyber Incident Feed Generator - Setup Script")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required")
        return False
    
    print(f"✅ Python version: {sys.version}")
    
    # Install dependencies
    if not run_command("pip install -r requirements.txt", "Installing dependencies"):
        return False
    
    # Create logs directory
    if not os.path.exists("logs"):
        os.makedirs("logs")
        print("✅ Created logs directory")
    
    # Initialize database and train model
    if not run_command("python main.py init", "Initializing system"):
        return False
    
    print("\n🎉 Setup completed successfully!")
    print("\n📚 Quick Start Commands:")
    print("  python main.py dashboard   # Start dashboard")
    print("  python main.py scheduler   # Start background automation")
    print("  python main.py all         # Start everything")
    print("\n📖 For more information, see README.md")
    
    return True

if __name__ == "__main__":
    success = setup_project()
    sys.exit(0 if success else 1)



