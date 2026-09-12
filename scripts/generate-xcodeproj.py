#!/usr/bin/env python3
"""Generate ServerOS.xcodeproj.

Xcode 16 introduced `PBXFileSystemSynchronizedRootGroup`, which lets a target
reference a *folder* instead of enumerating every file. That is what makes a
hand-generated project practical: adding a Swift file never touches the project
file, so this generator does not have to stay in sync with the source tree, and
there is no per-file build-phase bookkeeping to get wrong.

Run:  python3 scripts/generate-xcodeproj.py
Output: macos/ServerOS.xcodeproj/project.pbxproj (+ workspace scaffolding)

Regenerating is safe and idempotent: the ids are derived from stable names, so
the file does not churn between runs.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
MACOS = REPO / "macos"
PROJECT = MACOS / "ServerOS.xcodeproj"

APP_NAME = "ServerOS"
BUNDLE_ID = "com.orionsystems.ServerOS"
DEPLOYMENT_TARGET = "14.0"
# Swift 5 language mode. The compiler is Swift 6, but strict concurrency
# checking on a codebase this size would produce hundreds of diagnostics that
# have nothing to do with correctness on macOS 14. Migration is tracked in
# docs/ROADMAP.md; it is a deliberate staging decision, not an oversight.
SWIFT_VERSION = "5.0"
MARKETING_VERSION = "0.1.0"
BUILD_VERSION = "1"


def oid(name: str) -> str:
    """A stable 24-hex-character object id derived from a name."""
    return hashlib.sha256(name.encode()).hexdigest()[:24].upper()


# --- object ids -------------------------------------------------------------

IDS = {
    k: oid(k)
    for k in [
        "project",
        "mainGroup",
        "productsGroup",
        "appTarget",
        "testTarget",
        "appProduct",
        "testProduct",
        "appSourcesPhase",
        "appFrameworksPhase",
        "appResourcesPhase",
        "testSourcesPhase",
        "testFrameworksPhase",
        "testResourcesPhase",
        "appSyncGroup",
        "testSyncGroup",
        "projectConfigList",
        "appConfigList",
        "testConfigList",
        "projectDebug",
        "projectRelease",
        "appDebug",
        "appRelease",
        "testDebug",
        "testRelease",
        "testTargetDependency",
        "testContainerProxy",
        # Swift package references
        "pkgNIO",
        "pkgNIOSSH",
        "pkgCrypto",
        "prodNIOCore",
        "prodNIOPosix",
        "prodNIOSSH",
        "prodCrypto",
        "buildNIOCore",
        "buildNIOPosix",
        "buildNIOSSH",
        "buildCrypto",
    ]
}

PACKAGES = [
    # (id key, url, minimum version, [(product id key, build id key, product name)])
    (
        "pkgNIO",
        "https://github.com/apple/swift-nio.git",
        "2.102.0",
        [("prodNIOCore", "buildNIOCore", "NIOCore"), ("prodNIOPosix", "buildNIOPosix", "NIOPosix")],
    ),
    (
        "pkgNIOSSH",
        "https://github.com/apple/swift-nio-ssh.git",
        "0.15.0",
        [("prodNIOSSH", "buildNIOSSH", "NIOSSH")],
    ),
    (
        "pkgCrypto",
        "https://github.com/apple/swift-crypto.git",
        "3.0.0",
        [("prodCrypto", "buildCrypto", "Crypto")],
    ),
]


def build_files() -> str:
    lines = []
    for _, _, _, products in PACKAGES:
        for prod_key, build_key, name in products:
            lines.append(
                f"\t\t{IDS[build_key]} /* {name} in Frameworks */ = {{isa = PBXBuildFile; "
                f"productRef = {IDS[prod_key]} /* {name} */; }};"
            )
    return "\n".join(lines)


def package_references() -> str:
    lines = []
    for key, url, version, _ in PACKAGES:
        lines.append(
            f"\t\t{IDS[key]} /* XCRemoteSwiftPackageReference \"{url.rsplit('/', 1)[-1]}\" */ = {{\n"
            f"\t\t\tisa = XCRemoteSwiftPackageReference;\n"
            f'\t\t\trepositoryURL = "{url}";\n'
            f"\t\t\trequirement = {{\n"
            f"\t\t\t\tkind = upToNextMajorVersion;\n"
            f"\t\t\t\tminimumVersion = {version};\n"
            f"\t\t\t}};\n"
            f"\t\t}};"
        )
    return "\n".join(lines)


def product_dependencies() -> str:
    lines = []
    for key, _, _, products in PACKAGES:
        for prod_key, _, name in products:
            lines.append(
                f"\t\t{IDS[prod_key]} /* {name} */ = {{\n"
                f"\t\t\tisa = XCSwiftPackageProductDependency;\n"
                f"\t\t\tpackage = {IDS[key]};\n"
                f"\t\t\tproductName = {name};\n"
                f"\t\t}};"
            )
    return "\n".join(lines)


def framework_files() -> str:
    return ",\n".join(
        f"\t\t\t\t{IDS[build_key]} /* {name} in Frameworks */"
        for _, _, _, products in PACKAGES
        for _, build_key, name in products
    )


def package_list() -> str:
    return ",\n".join(
        f"\t\t\t\t{IDS[key]} /* XCRemoteSwiftPackageReference */" for key, _, _, _ in PACKAGES
    )


def target_product_list() -> str:
    return ",\n".join(
        f"\t\t\t\t{IDS[prod_key]} /* {name} */"
        for _, _, _, products in PACKAGES
        for prod_key, _, name in products
    )


SHARED_BUILD_SETTINGS = f"""
\t\t\t\tALWAYS_SEARCH_USER_PATHS = NO;
\t\t\t\tCLANG_ENABLE_MODULES = YES;
\t\t\t\tCLANG_ENABLE_OBJC_ARC = YES;
\t\t\t\tCOPY_PHASE_STRIP = NO;
\t\t\t\tENABLE_STRICT_OBJC_MSGSEND = YES;
\t\t\t\tGCC_NO_COMMON_BLOCKS = YES;
\t\t\t\tMACOSX_DEPLOYMENT_TARGET = {DEPLOYMENT_TARGET};
\t\t\t\tSDKROOT = macosx;
\t\t\t\tSWIFT_VERSION = {SWIFT_VERSION};
\t\t\t\tCLANG_WARN_BOOL_CONVERSION = YES;
\t\t\t\tCLANG_WARN_CONSTANT_CONVERSION = YES;
\t\t\t\tCLANG_WARN_DOCUMENTATION_COMMENTS = YES;
\t\t\t\tCLANG_WARN_EMPTY_BODY = YES;
\t\t\t\tCLANG_WARN_ENUM_CONVERSION = YES;
\t\t\t\tCLANG_WARN_INFINITE_RECURSION = YES;
\t\t\t\tCLANG_WARN_INT_CONVERSION = YES;
\t\t\t\tCLANG_WARN_UNREACHABLE_CODE = YES;
\t\t\t\tGCC_WARN_UNINITIALIZED_AUTOS = YES_AGGRESSIVE;
\t\t\t\tGCC_WARN_UNUSED_FUNCTION = YES;
\t\t\t\tGCC_WARN_UNUSED_VARIABLE = YES;
"""

APP_BUILD_SETTINGS = f"""
\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;
\t\t\t\tCODE_SIGN_ENTITLEMENTS = ServerOS/Resources/ServerOS.entitlements;
\t\t\t\tCODE_SIGN_STYLE = Automatic;
\t\t\t\tCOMBINE_HIDPI_IMAGES = YES;
\t\t\t\tCURRENT_PROJECT_VERSION = {BUILD_VERSION};
\t\t\t\tENABLE_HARDENED_RUNTIME = YES;
\t\t\t\tGENERATE_INFOPLIST_FILE = NO;
\t\t\t\tINFOPLIST_FILE = ServerOS/Resources/Info.plist;
\t\t\t\tLD_RUNPATH_SEARCH_PATHS = (
\t\t\t\t\t"$(inherited)",
\t\t\t\t\t"@executable_path/../Frameworks",
\t\t\t\t);
\t\t\t\tMARKETING_VERSION = {MARKETING_VERSION};
\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = {BUNDLE_ID};
\t\t\t\tPRODUCT_NAME = "$(TARGET_NAME)";
\t\t\t\tSWIFT_EMIT_LOC_STRINGS = YES;
"""

TEST_BUILD_SETTINGS = f"""
\t\t\t\tBUNDLE_LOADER = "$(TEST_HOST)";
\t\t\t\tCODE_SIGN_STYLE = Automatic;
\t\t\t\tCURRENT_PROJECT_VERSION = {BUILD_VERSION};
\t\t\t\tGENERATE_INFOPLIST_FILE = YES;
\t\t\t\tMARKETING_VERSION = {MARKETING_VERSION};
\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = {BUNDLE_ID}.Tests;
\t\t\t\tPRODUCT_NAME = "$(TARGET_NAME)";
\t\t\t\tSWIFT_EMIT_LOC_STRINGS = NO;
\t\t\t\tTEST_HOST = "$(BUILT_PRODUCTS_DIR)/{APP_NAME}.app/Contents/MacOS/{APP_NAME}";
"""


def pbxproj() -> str:
    return f"""// !$*UTF8*$!
{{
	archiveVersion = 1;
	classes = {{
	}};
	objectVersion = 77;
	objects = {{

/* Begin PBXBuildFile section */
{build_files()}
/* End PBXBuildFile section */

/* Begin PBXContainerItemProxy section */
		{IDS['testContainerProxy']} /* PBXContainerItemProxy */ = {{
			isa = PBXContainerItemProxy;
			containerPortal = {IDS['project']} /* Project object */;
			proxyType = 1;
			remoteGlobalIDString = {IDS['appTarget']};
			remoteInfo = {APP_NAME};
		}};
/* End PBXContainerItemProxy section */

/* Begin PBXFileReference section */
		{IDS['appProduct']} /* {APP_NAME}.app */ = {{isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = {APP_NAME}.app; sourceTree = BUILT_PRODUCTS_DIR; }};
		{IDS['testProduct']} /* {APP_NAME}Tests.xctest */ = {{isa = PBXFileReference; explicitFileType = wrapper.cfbundle; includeInIndex = 0; path = {APP_NAME}Tests.xctest; sourceTree = BUILT_PRODUCTS_DIR; }};
/* End PBXFileReference section */

/* Begin PBXFileSystemSynchronizedRootGroup section */
		{IDS['appSyncGroup']} /* {APP_NAME} */ = {{
			isa = PBXFileSystemSynchronizedRootGroup;
			path = {APP_NAME};
			sourceTree = "<group>";
		}};
		{IDS['testSyncGroup']} /* {APP_NAME}Tests */ = {{
			isa = PBXFileSystemSynchronizedRootGroup;
			path = {APP_NAME}Tests;
			sourceTree = "<group>";
		}};
/* End PBXFileSystemSynchronizedRootGroup section */

/* Begin PBXFrameworksBuildPhase section */
		{IDS['appFrameworksPhase']} /* Frameworks */ = {{
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
{framework_files()},
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
		{IDS['testFrameworksPhase']} /* Frameworks */ = {{
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
/* End PBXFrameworksBuildPhase section */

/* Begin PBXGroup section */
		{IDS['mainGroup']} = {{
			isa = PBXGroup;
			children = (
				{IDS['appSyncGroup']} /* {APP_NAME} */,
				{IDS['testSyncGroup']} /* {APP_NAME}Tests */,
				{IDS['productsGroup']} /* Products */,
			);
			sourceTree = "<group>";
		}};
		{IDS['productsGroup']} /* Products */ = {{
			isa = PBXGroup;
			children = (
				{IDS['appProduct']} /* {APP_NAME}.app */,
				{IDS['testProduct']} /* {APP_NAME}Tests.xctest */,
			);
			name = Products;
			sourceTree = "<group>";
		}};
/* End PBXGroup section */

/* Begin PBXNativeTarget section */
		{IDS['appTarget']} /* {APP_NAME} */ = {{
			isa = PBXNativeTarget;
			buildConfigurationList = {IDS['appConfigList']} /* Build configuration list for PBXNativeTarget "{APP_NAME}" */;
			buildPhases = (
				{IDS['appSourcesPhase']} /* Sources */,
				{IDS['appFrameworksPhase']} /* Frameworks */,
				{IDS['appResourcesPhase']} /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
			);
			fileSystemSynchronizedGroups = (
				{IDS['appSyncGroup']} /* {APP_NAME} */,
			);
			name = {APP_NAME};
			packageProductDependencies = (
{target_product_list()},
			);
			productName = {APP_NAME};
			productReference = {IDS['appProduct']} /* {APP_NAME}.app */;
			productType = "com.apple.product-type.application";
		}};
		{IDS['testTarget']} /* {APP_NAME}Tests */ = {{
			isa = PBXNativeTarget;
			buildConfigurationList = {IDS['testConfigList']} /* Build configuration list for PBXNativeTarget "{APP_NAME}Tests" */;
			buildPhases = (
				{IDS['testSourcesPhase']} /* Sources */,
				{IDS['testFrameworksPhase']} /* Frameworks */,
				{IDS['testResourcesPhase']} /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
				{IDS['testTargetDependency']} /* PBXTargetDependency */,
			);
			fileSystemSynchronizedGroups = (
				{IDS['testSyncGroup']} /* {APP_NAME}Tests */,
			);
			name = {APP_NAME}Tests;
			productName = {APP_NAME}Tests;
			productReference = {IDS['testProduct']} /* {APP_NAME}Tests.xctest */;
			productType = "com.apple.product-type.bundle.unit-test";
		}};
/* End PBXNativeTarget section */

/* Begin PBXProject section */
		{IDS['project']} /* Project object */ = {{
			isa = PBXProject;
			attributes = {{
				BuildIndependentTargetsInParallel = 1;
				LastSwiftUpdateCheck = 1600;
				LastUpgradeCheck = 1600;
				TargetAttributes = {{
					{IDS['appTarget']} = {{
						CreatedOnToolsVersion = 16.0;
					}};
					{IDS['testTarget']} = {{
						CreatedOnToolsVersion = 16.0;
						TestTargetID = {IDS['appTarget']};
					}};
				}};
			}};
			buildConfigurationList = {IDS['projectConfigList']} /* Build configuration list for PBXProject "{APP_NAME}" */;
			developmentRegion = en;
			hasScannedForEncodings = 0;
			knownRegions = (
				en,
				Base,
			);
			mainGroup = {IDS['mainGroup']};
			minimizedProjectReferenceProxies = 1;
			packageReferences = (
{package_list()},
			);
			preferredProjectObjectVersion = 77;
			productRefGroup = {IDS['productsGroup']} /* Products */;
			projectDirPath = "";
			projectRoot = "";
			targets = (
				{IDS['appTarget']} /* {APP_NAME} */,
				{IDS['testTarget']} /* {APP_NAME}Tests */,
			);
		}};
/* End PBXProject section */

/* Begin PBXResourcesBuildPhase section */
		{IDS['appResourcesPhase']} /* Resources */ = {{
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
		{IDS['testResourcesPhase']} /* Resources */ = {{
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
/* End PBXResourcesBuildPhase section */

/* Begin PBXSourcesBuildPhase section */
		{IDS['appSourcesPhase']} /* Sources */ = {{
			isa = PBXSourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
		{IDS['testSourcesPhase']} /* Sources */ = {{
			isa = PBXSourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
/* End PBXSourcesBuildPhase section */

/* Begin PBXTargetDependency section */
		{IDS['testTargetDependency']} /* PBXTargetDependency */ = {{
			isa = PBXTargetDependency;
			target = {IDS['appTarget']} /* {APP_NAME} */;
			targetProxy = {IDS['testContainerProxy']} /* PBXContainerItemProxy */;
		}};
/* End PBXTargetDependency section */

/* Begin XCBuildConfiguration section */
		{IDS['projectDebug']} /* Debug */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{{SHARED_BUILD_SETTINGS}\t\t\t\tDEBUG_INFORMATION_FORMAT = dwarf;
				ENABLE_TESTABILITY = YES;
				GCC_OPTIMIZATION_LEVEL = 0;
				GCC_PREPROCESSOR_DEFINITIONS = (
					"DEBUG=1",
					"$(inherited)",
				);
				MTL_ENABLE_DEBUG_INFO = INCLUDE_SOURCE;
				ONLY_ACTIVE_ARCH = YES;
				SWIFT_ACTIVE_COMPILATION_CONDITIONS = "DEBUG $(inherited)";
				SWIFT_OPTIMIZATION_LEVEL = "-Onone";
			}};
			name = Debug;
		}};
		{IDS['projectRelease']} /* Release */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{{SHARED_BUILD_SETTINGS}\t\t\t\tDEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";
				ENABLE_NS_ASSERTIONS = NO;
				MTL_ENABLE_DEBUG_INFO = NO;
				SWIFT_COMPILATION_MODE = wholemodule;
				SWIFT_OPTIMIZATION_LEVEL = "-O";
				VALIDATE_PRODUCT = YES;
			}};
			name = Release;
		}};
		{IDS['appDebug']} /* Debug */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{{APP_BUILD_SETTINGS}\t\t\t}};
			name = Debug;
		}};
		{IDS['appRelease']} /* Release */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{{APP_BUILD_SETTINGS}\t\t\t}};
			name = Release;
		}};
		{IDS['testDebug']} /* Debug */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{{TEST_BUILD_SETTINGS}\t\t\t}};
			name = Debug;
		}};
		{IDS['testRelease']} /* Release */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{{TEST_BUILD_SETTINGS}\t\t\t}};
			name = Release;
		}};
/* End XCBuildConfiguration section */

/* Begin XCConfigurationList section */
		{IDS['projectConfigList']} /* Build configuration list for PBXProject "{APP_NAME}" */ = {{
			isa = XCConfigurationList;
			buildConfigurations = (
				{IDS['projectDebug']} /* Debug */,
				{IDS['projectRelease']} /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		}};
		{IDS['appConfigList']} /* Build configuration list for PBXNativeTarget "{APP_NAME}" */ = {{
			isa = XCConfigurationList;
			buildConfigurations = (
				{IDS['appDebug']} /* Debug */,
				{IDS['appRelease']} /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		}};
		{IDS['testConfigList']} /* Build configuration list for PBXNativeTarget "{APP_NAME}Tests" */ = {{
			isa = XCConfigurationList;
			buildConfigurations = (
				{IDS['testDebug']} /* Debug */,
				{IDS['testRelease']} /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		}};
/* End XCConfigurationList section */

/* Begin XCRemoteSwiftPackageReference section */
{package_references()}
/* End XCRemoteSwiftPackageReference section */

/* Begin XCSwiftPackageProductDependency section */
{product_dependencies()}
/* End XCSwiftPackageProductDependency section */
	}};
	rootObject = {IDS['project']} /* Project object */;
}}
"""


SCHEME = f"""<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion = "1600" version = "1.7">
   <BuildAction parallelizeBuildables = "YES" buildImplicitDependencies = "YES">
      <BuildActionEntries>
         <BuildActionEntry buildForTesting = "YES" buildForRunning = "YES" buildForProfiling = "YES" buildForArchiving = "YES" buildForAnalyzing = "YES">
            <BuildableReference
               BuildableIdentifier = "primary"
               BlueprintIdentifier = "{IDS['appTarget']}"
               BuildableName = "{APP_NAME}.app"
               BlueprintName = "{APP_NAME}"
               ReferencedContainer = "container:{APP_NAME}.xcodeproj">
            </BuildableReference>
         </BuildActionEntry>
      </BuildActionEntries>
   </BuildAction>
   <TestAction buildConfiguration = "Debug" selectedDebuggerIdentifier = "Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier = "Xcode.DebuggerFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv = "YES">
      <Testables>
         <TestableReference skipped = "NO">
            <BuildableReference
               BuildableIdentifier = "primary"
               BlueprintIdentifier = "{IDS['testTarget']}"
               BuildableName = "{APP_NAME}Tests.xctest"
               BlueprintName = "{APP_NAME}Tests"
               ReferencedContainer = "container:{APP_NAME}.xcodeproj">
            </BuildableReference>
         </TestableReference>
      </Testables>
   </TestAction>
   <LaunchAction buildConfiguration = "Debug" selectedDebuggerIdentifier = "Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier = "Xcode.DebuggerFoundation.Launcher.LLDB" launchStyle = "0" useCustomWorkingDirectory = "NO" ignoresPersistentStateOnLaunch = "NO" debugDocumentVersioning = "YES" debugServiceExtension = "internal" allowLocationSimulation = "YES">
      <BuildableProductRunnable runnableDebuggingMode = "0">
         <BuildableReference
            BuildableIdentifier = "primary"
            BlueprintIdentifier = "{IDS['appTarget']}"
            BuildableName = "{APP_NAME}.app"
            BlueprintName = "{APP_NAME}"
            ReferencedContainer = "container:{APP_NAME}.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </LaunchAction>
   <ProfileAction buildConfiguration = "Release" shouldUseLaunchSchemeArgsEnv = "YES" savedToolIdentifier = "" useCustomWorkingDirectory = "NO" debugDocumentVersioning = "YES">
      <BuildableProductRunnable runnableDebuggingMode = "0">
         <BuildableReference
            BuildableIdentifier = "primary"
            BlueprintIdentifier = "{IDS['appTarget']}"
            BuildableName = "{APP_NAME}.app"
            BlueprintName = "{APP_NAME}"
            ReferencedContainer = "container:{APP_NAME}.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </ProfileAction>
   <AnalyzeAction buildConfiguration = "Debug"></AnalyzeAction>
   <ArchiveAction buildConfiguration = "Release" revealArchiveInOrganizer = "YES"></ArchiveAction>
</Scheme>
"""

WORKSPACE_DATA = """<?xml version="1.0" encoding="UTF-8"?>
<Workspace version = "1.0">
   <FileRef location = "self:"></FileRef>
</Workspace>
"""

WORKSPACE_SETTINGS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>BuildSystemType</key>
	<string>Latest</string>
	<key>PreviewsEnabled</key>
	<true/>
</dict>
</plist>
"""


def main() -> int:
    if not (MACOS / APP_NAME).is_dir():
        print(f"error: {MACOS / APP_NAME} does not exist", file=sys.stderr)
        return 1

    PROJECT.mkdir(parents=True, exist_ok=True)
    (PROJECT / "project.pbxproj").write_text(pbxproj(), encoding="utf-8")

    ws = PROJECT / "project.xcworkspace"
    ws.mkdir(exist_ok=True)
    (ws / "contents.xcworkspacedata").write_text(WORKSPACE_DATA, encoding="utf-8")
    shared = ws / "xcshareddata"
    shared.mkdir(exist_ok=True)
    (shared / "WorkspaceSettings.xcsettings").write_text(WORKSPACE_SETTINGS, encoding="utf-8")

    schemes = PROJECT / "xcshareddata" / "xcschemes"
    schemes.mkdir(parents=True, exist_ok=True)
    (schemes / f"{APP_NAME}.xcscheme").write_text(SCHEME, encoding="utf-8")

    swift_count = len(list((MACOS / APP_NAME).rglob("*.swift")))
    test_count = len(list((MACOS / f"{APP_NAME}Tests").rglob("*.swift"))) if (MACOS / f"{APP_NAME}Tests").is_dir() else 0
    print(f"wrote {PROJECT.relative_to(REPO)}")
    print(f"  app target   : {swift_count} Swift files (folder-synchronized)")
    print(f"  test target  : {test_count} Swift files")
    print(f"  packages     : {', '.join(u.rsplit('/', 1)[-1] for _, u, _, _ in PACKAGES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
