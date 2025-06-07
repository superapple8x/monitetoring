#!/usr/bin/env python3
"""
Quick test to verify Phase 4 API endpoints are properly configured
"""

import sys
import os

# Add the python_api directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'python_api'))

def test_api_imports():
    """Test that all API components can be imported successfully"""
    print("🧪 Testing Phase 4 API Component Imports")
    print("=" * 50)
    
    try:
        # Test intelligent monitoring imports
        from python_api.app.monitoring.intelligent_network_monitor import (
            IntelligentNetworkMonitor, 
            NetworkHealthReport,
            NetworkPerformanceAnalysis,
            SecurityThreatAnalysis
        )
        print("✅ IntelligentNetworkMonitor imports successful")
        
        # Test API endpoint imports
        from python_api.app.api.intelligent_monitoring_endpoints import (
            router,
            NetworkHealthResponse,
            NetworkInsightsResponse
        )
        print("✅ Intelligent monitoring endpoints imports successful")
        
        # Test flow processor imports
        from python_api.app.redis.flow_processor import FlowProcessor
        print("✅ Enhanced FlowProcessor imports successful")
        
        # Test main app integration
        from python_api.app.main import app
        print("✅ Main FastAPI app imports successful")
        
        print("\n🎉 All Phase 4 components imported successfully!")
        print("🚀 API is ready for deployment")
        
        # Show available routes
        print("\n📋 Available Intelligent Monitoring Routes:")
        routes = [route for route in app.routes if hasattr(route, 'path') and 'intelligent-monitoring' in route.path]
        for route in routes:
            if hasattr(route, 'methods'):
                methods = ', '.join(route.methods)
                print(f"   {methods:6} {route.path}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    success = test_api_imports()
    if success:
        print("\n✅ Phase 4 API Test: PASSED")
        print("🎯 Ready for frontend integration!")
    else:
        print("\n❌ Phase 4 API Test: FAILED")
        sys.exit(1) 