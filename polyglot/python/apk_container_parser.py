import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional


class APKContainerParser:
    """MASTG-aligned Android APK container parser with zero dependencies."""

    # MASTG-relevant permission categories
    DANGEROUS_PERMISSIONS = {
        'android.permission.CAMERA',
        'android.permission.READ_CONTACTS',
        'android.permission.RECEIVE_BOOT_COMPLETED',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
        'android.permission.RECORD_AUDIO',
        'android.permission.CALL_PHONE',
        'android.permission.GET_ACCOUNTS',
        'android.permission.USE_CREDENTIALS',
        'android.permission.POST_NOTIFICATIONS',
    }

    # Entry point components
    ENTRY_POINTS = {
        'activity': 'android.intent.category.LAUNCHER',
        'receiver': 'android.intent.category.DEFAULT',
    }

    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self.manifest_root: Optional[ET.Element] = None
        self.container_info: Dict[str, Any] = {}

    def parse(self) -> Dict[str, Any]:
        """Parse the APK and return structured container information."""
        result = {
            'path': str(self.apk_path),
            'name': self._get_apk_name(),
            'version_code': self._get_version_code(),
            'version_name': self._get_version_name(),
            'package_name': self._get_package_name(),
            'entry_points': self._find_entry_points(),
            'permissions': {
                'all': self._extract_permissions(),
                'dangerous': [p for p in self._extract_permissions() 
                            if p in self.DANGEROUS_PERMISSIONS],
            },
            'native_libraries': self._find_native_libs(),
            'resource_files': self._find_resource_files(),
            'manifest_sections': {
                'activities': self._find_activities(),
                'services': self._find_services(),
                'receivers': self._find_receivers(),
                'broadcast_receivers': self._find_broadcast_receivers(),
                'providers': self._find_providers(),
            },
        }

        return result

    def _get_apk_name(self) -> str:
        """Extract APK name from path."""
        return self.apk_path.name

    def _get_version_code(self) -> Optional[int]:
        """Extract versionCode from AndroidManifest.xml"""
        if not self.manifest_root:
            self._parse_manifest()
        
        if self.manifest_root is None:
            return None
        
        try:
            # Navigate to <application> -> <meta-data android:name="android.versionCode">
            app_elem = self.manifest_root.find('.//application')
            if app_elem is not None:
                meta_data = app_elem.find(
                    './/meta-data[@android:name="android.versionCode"]'
                )
                if meta_data is not None and meta_data.text:
                    return int(meta_data.text)
        except (ValueError, TypeError):
            pass
        
        return None

    def _get_version_name(self) -> Optional[str]:
        """Extract versionName from AndroidManifest.xml"""
        if not self.manifest_root:
            self._parse_manifest()
        
        if self.manifest_root is None:
            return None
        
        try:
            app_elem = self.manifest_root.find('.//application')
            if app_elem is not None:
                meta_data = app_elem.find(
                    './/meta-data[@android:name="android.versionName"]'
                )
                if meta_data is not None and meta_data.text:
                    return meta_data.text
        except (ValueError, TypeError):
            pass
        
        return None

    def _get_package_name(self) -> Optional[str]:
        """Extract package name from AndroidManifest.xml"""
        if not self.manifest_root:
            self._parse_manifest()
        
        if self.manifest_root is None:
            return None
        
        try:
            # Check for manifest attribute first (Android 12+)
            if 'package' in self.manifest_root.attrib:
                return self.manifest_root.attrib['package']
            
            # Fallback to application element
            app_elem = self.manifest_root.find('.//application')
            if app_elem is not None and 'name' in app_elem.attrib:
                return app_elem.attrib['name']
        except (ValueError, TypeError):
            pass
        
        return None

    def _parse_manifest(self) -> None:
        """Parse AndroidManifest.xml into ElementTree"""
        manifest_path = self.apk_path / 'AndroidManifest.xml'
        
        if not manifest_path.exists():
            self.manifest_root = None
            return
        
        try:
            tree = ET.parse(manifest_path)
            self.manifest_root = tree.getroot()
            
            # Handle namespace (AndroidManifest.xml v2.0+)
            ns_map = {'android': 'http://schemas.android.com/apk/res/android'}
            if '{' in str(self.manifest_root.tag):
                self.manifest_root = self.manifest_root[0]  # Strip namespace
                
        except ET.ParseError as e:
            print(f"Warning: Manifest parse error: {e}")
            self.manifest_root = None

    def _find_entry_points(self) -> List[Dict[str, Any]]:
        """Find all entry point components (activities, receivers)."""
        if not self.manifest_root:
            return []
        
        entries = []
        
        # Find activities with LAUNCHER category
        launcher_activities = self._find_activities(
            './/activity[@android:name]'
        )
        for act in launcher_activities:
            name = act.get('name', '')
            if 'LAUNCHER' in str(act.attrib):
                entries.append({
                    'type': 'launcher_activity',
                    'name': name,
                })
        
        # Find broadcast receivers with DEFAULT category
        default_receivers = self._find_broadcast_receivers(
            './/receiver[@android:name]'
        )
        for recv in default_receivers:
            name = recv.get('name', '')
            if 'DEFAULT' in str(recv.attrib):
                entries.append({
                    'type': 'default_receiver',
                    'name': name,
                })
        
        return entries

    def _find_activities(self, xpath: str) -> List[ET.Element]:
        """Find activity elements matching xpath."""
        if not self.manifest_root:
            return []
        
        try:
            # Handle namespace in xpath
            ns = 'android:'
            app_elem = self.manifest_root.find('.//application')
            activities = []
            
            if app_elem is not None:
                for act in app_elem.findall(xpath, {'android': ns}):
                    activities.append(act)
                
                # Also check without namespace prefix (older manifests)
                for act in app_elem.findall(xpath):
                    if 'name' in act.attrib and act.get('name'):
                        activities.append(act)
            
            return activities
            
        except Exception:
            return []

    def _find_services(self, xpath: str = './/service') -> List[ET.Element]:
        """Find service elements."""
        if not self.manifest_root:
            return []
        
        try:
            ns = 'android:'
            app_elem = self.manifest_root.find('.//application')
            
            services = []
            if app_elem is not None:
                for svc in app_elem.findall(xpath, {'android': ns}):
                    services.append(svc)
                
                # Fallback without namespace
                for svc in app_elem.findall(xpath):
                    if 'name' in svc.attrib and svc.get('name'):
                        services.append(svc)
            
            return services
            
        except Exception:
            return []

    def _find_receivers(self, xpath: str = './/receiver') -> List[ET.Element]:
        """Find receiver elements."""
        if not self.manifest_root:
            return []
        
        try:
            ns = 'android:'
            app_elem = self.manifest_root.find('.//application')
            
            receivers = []
            if app_elem is not None:
                for recv in app_elem.findall(xpath, {'android': ns}):
                    receivers.append(recv)
                
                # Fallback without namespace
                for recv in app_elem.findall(xpath):
                    if 'name' in recv.attrib and recv.get('name'):
                        receivers.append(recv)
            
            return receivers
            
        except Exception:
            return []

    def _find_broadcast_receivers(self, xpath: str = './/receiver') -> List[ET.Element]:
        """Find broadcast receiver elements."""
        if not self.manifest_root:
            return []
        
        try:
            ns = 'android:'
            app_elem = self.manifest_root.find('.//application')
            
            receivers = []
            if app_elem is not None:
                for recv in app_elem.findall(xpath, {'android': ns}):
                    # Check if it's a broadcast receiver (has intent filter)
                    has_intent_filter = 'intent-filter' in str(recv.attrib) or \
                                       any('intent-filter' in str(c.tag) 
                                           for c in recv.iter())
                    
                    if has_intent_filter:
                        receivers.append(recv)
                
                # Fallback without namespace
                for recv in app_elem.findall(xpath):
                    if 'name' in recv.attrib and recv.get('name'):
                        has_if = 'intent-filter' in str(recv.attrib) or \
                                 any('intent-filter' in str(c.tag) 
                                     for c in recv.iter())
                        if has_if:
                            receivers.append(recv)
            
            return receivers
            
        except Exception:
            return []

    def _find_providers(self, xpath: str = './/provider') -> List[ET.Element]:
        """Find content provider elements."""
        if not self.manifest_root:
            return []
        
        try:
            ns = 'android:'
            app_elem = self.manifest_root.find('.//application')
            
            providers = []
            if app_elem is not None:
                for prov in app_elem.findall(xpath, {'android': ns}):
                    providers.append(prov)
                
                # Fallback without namespace
                for prov in app_elem.findall(xpath):
                    if 'name' in prov.attrib and prov.get('name'):
                        providers.append(prov)
            
            return providers
            
        except Exception:
            return []

    def _extract_permissions(self) -> List[str]:
        """Extract all declared permissions from manifest."""
        if not self.manifest_root:
            return []
        
        result = []
        
        try:
            ns = 'android:'
            app_elem = self.manifest_root.find('.//application')
            
            if app_elem is not None:
                # Check for uses-permission elements
                perms = app_elem.findall(
                    './/uses-permission[@android:name]',
                    {'android': ns}
                )
                
                for perm in perms:
                    name = perm.get('name', '')
                    if name and 'name' not in result:
                        result.append(name)
                    
                    # Also check without namespace prefix
                    if '{' in str(perm.tag):
                        alt_name = perm.attrib.get('name', '').split('"')[1]
                        if alt_name and alt_name not in result:
                            result.append(alt_name)
            
        except Exception:
            pass
        
        return list(set(result))

    def _find_native_libs(self) -> List[Dict[str, Any]]:
        """Find native library files (lib/ directories)."""
        lib_dirs = []
        
        for arch in ['armeabi', 'arm64-v8a', 'x86', 'x86_64']:
            path = self.apk_path / 'lib' / arch
            
            if path.exists():
                files = list(path.iterdir())
                lib_dirs.append({
                    'architecture': arch,
                    'path': str(path),
                    'files': [f.name for f in files],
                    'count': len(files),
                })
        
        return lib_dirs

    def _find_resource_files(self) -> Dict[str, List[str]]:
        """Find resource file categories."""
        resources = {
            'drawable': [],
            'raw': [],
            'xml': [],
            'values': [],
            'res_values': [],
        }
        
        res_path = self.apk_path / 'res'
        
        if not res_path.exists():
            return resources
        
        for category in ['drawable', 'raw', 'xml', 'values']:
            cat_path = res_path / category
            
            if cat_path.exists():
                files = [f.name for f in cat_path.iterdir() 
                        if f.is_file()]
                resources[category] = files
        
        return resources

    def _get_resource_count(self) -> int:
        """Get total resource file count."""
        res_path = self.apk_path / 'res'
        
        if not res_path.exists():
            return 0
        
        total = 0
        for category in ['drawable', 'raw', 'xml', 'values']:
            cat_path = res_path / category
            
            if cat_path.exists():
                total += len(list(cat_path.iterdir()))
        
        return total

    def _get_file_size(self) -> int:
        """Get APK file size in bytes."""
        try:
            return self.apk_path.stat().st_size
        except OSError:
            return 0

    @staticmethod
    def parse_apk(apk_path: str) -> Dict[str, Any]:
        """Static method for convenient calling."""
        parser = APKContainerParser(apk_path)
        return parser.parse()


# Demo / Entry Point
if __name__ == '__main__':
    import sys
    
    # Default to current directory if no argument provided
    apk_file = sys.argv[1] if len(sys.argv) > 1 else 'test.apk'
    
    print(f"APK Container Parser - MASTG Aligned")
    print("=" * 40)
    print(f"Target: {apk_file}")
    print()
    
    try:
        result = APKContainerParser.parse_apk(apk_file)
        
        # Print summary
        print("Summary:")
        print(f"  Name:       {result['name']}")
        print(f"  Package:    {result['package_name'] or 'Unknown'}")
        print(f"  Version:    {result['version_code'] or result['version_name'] or 'Unknown'}")
        print(f"  Size:       {result['_size']:,} bytes ({result['_size']/1024:.1f} KB)")
        print()
        
        # Print dangerous permissions
        if result['permissions']['dangerous']:
            print("DANGEROUS PERMISSIONS:")
            for perm in result['permissions']['dangerous']:
                print(f"  - {perm}")
            print()
        
        # Print entry points
        if result['entry_points']:
            print("ENTRY POINTS:")
            for ep in result['entry_points']:
                print(f"  - {ep['type']}: {ep['name']}")
            print()
        
        # Print native libraries
        if result['native_libraries']:
            print("NATIVE LIBRARIES:")
            for lib in result['native_libraries']:
                print(f"  [{lib['architecture']}] {lib['count']} files")
            print()
        
        # Print resource counts
        res_count = APKContainerParser._get_resource_count(apk_file)
        print(f"RESOURCE FILES: {res_count:,} total")
        
    except FileNotFoundError:
        print(f"Error: File not found - {apk_file}")
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing APK: {e}")
        sys.exit(1)