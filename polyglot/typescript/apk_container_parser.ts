// polyglot/typescript/apk_container_parser.ts
// MASTG-aligned Android APK static security analyzer
// Zero dependencies, from-scratch binary-AXML decoder

import * as fs from 'fs';
import * as path from 'path';

/**
 * ZIP local file header constants (PKZIP 2.04)
 */
const ZIP_MAGIC = 0x04034b50;
const ZIP_LOCAL_FILE_HEADER_SIZE = 30;
const ZIP_CENTRAL_DIR_SIGNATURE = 0x02014b50;

/**
 * AXML namespace constants (AndroidManifest.xml)
 */
const NAMESPACE_ANDROID = 'http://schemas.android.com/apk/res/android';
const NAMESPACE_ANDROID_10 = 'http://schemas.android.com/apk/res/android:1.0';

/**
 * DEX file header constants
 */
const DEX_MAGIC = 0x0d002a57;
const DEX_HEADER_SIZE = 64;

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

interface ZipEntry {
    name: string;
    compressionMethod: number;
    compressedSize: number;
    uncompressedSize: number;
    lastModTime: number;
    crc32: number;
}

interface AxmlElement {
    tag: string;
    attributes: Record<string, string>;
    children: AxmlElement[];
    text?: string;
}

interface ApkInfo {
    filename: string;
    path: string;
    size: number;
    versionCode: number | null;
    versionName: string | null;
    package_name: string | null;
    minSdkVersion: number | null;
    targetSdkVersion: number | null;
    mainActivity: string | null;
    signatureInfo: SignatureInfo[];
    permissions: { declared: Set<string>; requested: Set<string> };
    components: {
        activities: AxmlElement[];
        services: AxlElement[];
        broadcastReceivers: AxmlElement[];
        contentProviders: AxmlElement[];
    };
    dexInfo: DexInfo | null;
    rawManifest: string;
}

interface SignatureInfo {
    algorithm: string;
    digest: string;
    timestamp: number;
    certificateId: string;
}

interface DexInfo {
    magic: number;
    headerSize: number;
    checksumOffset: number;
    checksumSize: number;
    linkSize: number;
    linkOffset: number;
    classCount: number;
    classOffset: number;
    stringIdSize: number;
    stringIdOffset: number;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function readUInt16LE(buffer: Buffer, offset: number): number {
    return buffer.readUInt16LE(offset);
}

function readUInt32LE(buffer: Buffer, offset: number): number {
    return buffer.readUInt32LE(offset);
}

function readStringFromZipEntry(
    entry: ZipEntry,
    zipBuffer: Buffer,
    centralDirOffset: number
): string | null {
    const nameOffset = centralDirOffset + 46; // Name starts at offset 46 in central dir
    if (entry.compressionMethod === 0) {
        return zipBuffer.toString('utf8', nameOffset, nameOffset + entry.uncompressedSize);
    } else if (entry.compressionMethod === 8 || entry.compressionMethod === 9) {
        // Deflate or BZip2 - need to decompress
        const compressedDataStart = centralDirOffset + 50;
        const compressedDataEnd = centralDirOffset + 50 + entry.compressedSize;
        
        if (entry.compressionMethod === 8) {
            return inflateDeflate(zipBuffer, compressedDataStart, compressedDataEnd);
        } else if (entry.compressionMethod === 9) {
            return inflateBZip2(zipBuffer, compressedDataStart, compressedDataEnd);
        }
    }
    return null;
}

function inflateDeflate(
    buffer: Buffer,
    offset: number,
    endOffset: number
): string | null {
    try {
        const zlib = require('zlib');
        return zlib.inflateRawSync(buffer.slice(offset, endOffset)).toString();
    } catch (e) {
        // Fallback: return raw bytes as hex if deflate fails
        return buffer.slice(offset, endOffset).toString('hex');
    }
}

function inflateBZip2(
    buffer: Buffer,
    offset: number,
    endOffset: number
): string | null {
    try {
        const zlib = require('zlib');
        return zlib.inflateRawSync(buffer.slice(offset, endOffset)).toString();
    } catch (e) {
        return buffer.slice(offset, endOffset).toString('hex');
    }
}

function readAxmlElement(
    xml: string,
    offset: number = 0,
    depth: number = 0
): AxmlElement[] | null {
    const elements: AxmlElement[] = [];
    
    // Find opening tags
    let tagMatch;
    while ((tagMatch = /<\s*([a-zA-Z][a-zA-Z0-9_:.\-]*)/g.exec(xml)) !== null) {
        if (offset > 0 && xml.slice(offset - 1, offset).match(/[^\s>/]$/)) {
            // Not at start of tag
            break;
        }
        
        const tagName = tagMatch[1];
        let attributes: Record<string, string> = {};
        let textContent = '';
        
        // Parse attributes
        const attrMatch = /([a-zA-Z][a-zA-Z0-9_:.\-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))/g;
        while ((attrMatch.exec(xml)) !== null) {
            const [, name, quoted1, quoted2, unquoted] = attrMatch;
            if (name && quoted1 !== undefined) {
                attributes[name] = quoted1;
            } else if (name && quoted2 !== undefined) {
                attributes[name] = quoted2;
            } else if (name && unquoted !== undefined) {
                attributes[name] = unquoted;
            }
        }
        
        // Check for self-closing tag
        const closeMatch = xml.slice(tagMatch.index + tagName.length).match(/\/>/);
        let isSelfClosing = false;
        if (closeMatch) {
            isSelfClosing = true;
        } else {
            // Look for closing tag
            const closingTag = `</${tagName}>`;
            const closeIndex = xml.indexOf(closingTag, tagMatch.index + tagName.length);
            if (closeIndex > -1) {
                // Extract text content between opening and closing tags
                const contentStart = tagMatch.index + tagName.length;
                const contentEnd = closeIndex + closingTag.length;
                const innerContent = xml.slice(contentStart, contentEnd).trim();
                
                if (innerContent && !isSelfClosing) {
                    // Check for nested elements first
                    const childElements: AxmlElement[] = [];
                    let childMatch;
                    
                    while ((childMatch = /<\s*([a-zA-Z][a-zA-Z0-9_:.\-]*)/g.exec(innerContent)) !== null) {
                        if (innerContent.slice(childMatch.index, childMatch.index + 1).match(/^[^\s>/]/)) {
                            // Found nested element
                            const childTag = childMatch[1];
                            
                            // Extract attributes for child
                            const childAttrs: Record<string, string> = {};
                            const childAttrMatch = /([a-zA-Z][a-zA-Z0-9_:.\-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))/g;
                            
                            while ((childAttrMatch.exec(innerContent)) !== null) {
                                const [, cname, cquoted1, cquoted2, cunquoted] = childAttrMatch;
                                if (cname && cquoted1 !== undefined) {
                                    childAttrs[cname] = cquoted1;
                                } else if (cname && cquoted2 !== undefined) {
                                    childAttrs[cname] = cquoted2;
                                } else if (cname && cunquoted !== undefined) {
                                    childAttrs[cname] = cunquoted;
                                }
                            }
                            
                            const childElement: AxmlElement = {
                                tag: childTag,
                                attributes: childAttrs,
                                children: [],
                                text: innerContent.slice(childMatch.index + childTag.length).trim()
                                    .replace(new RegExp(`</${childTag}>`, 'g'), '')
                                    .trim(),
                            };
                            
                            // Check if child is self-closing or has content
                            const childClose = `</${childTag}>`;
                            const childCloseIndex = innerContent.indexOf(childClose, childMatch.index + childTag.length);
                            
                            if (childCloseIndex > -1) {
                                const childInnerStart = childMatch.index + childTag.length;
                                const childInnerEnd = childCloseIndex + childClose.length;
                                const childInnerContent = innerContent.slice(childInnerStart, childInnerEnd).trim();
                                
                                if (!childInnerContent.match(/\/>/)) {
                                    // Has content - parse recursively
                                    childElement.children.push(
                                        readAxmlElement(innerContent, childInnerStart) || []
                                    );
                                }
                            } else {
                                // Self-closing or no closing tag found
                                if (childInnerContent.match(/\/>/)) {
                                    isSelfClosing = true;
                                }
                            }
                            
                            childElements.push(childElement);
                        }
                    }
                    
                    elements.push({
                        tag,
                        attributes,
                        children: childElements,
                        text: innerContent.trim().replace(new RegExp(`</${tag}>`, 'g'), '').trim(),
                    });
                } else {
                    // Self-closing or empty content
                    if (!isSelfClosing) {
                        isSelfClosing = true;
                    }
                }
            }
        }
        
        offset += tagMatch[0].length;
    }
    
    return elements.length > 0 ? elements : null;
}

function parseAxml(xml: string): AxmlElement[] {
    // Remove XML declaration and DOCTYPE if present
    const cleanXml = xml.replace(/<\?xml[^>]*\?>/g, '').replace(/<!DOCTYPE[^>]*>/g, '');
    
    // Handle namespace prefix stripping for simpler parsing
    let processedXml = cleanXml;
    
    // Replace common namespace prefixes with their URIs
    const nsReplacements: Record<string, string> = {
        'android': NAMESPACE_ANDROID,
        'http://schemas.android.com/apk/res/android': NAMESPACE_ANDROID,
    };
    
    for (const [prefix, uri] of Object.entries(nsReplacements)) {
        processedXml = processedXml.replace(
            new RegExp(`\\b${prefix}:`, 'g'),
            `${uri}#`
        );
    }
    
    // Also handle URIs directly in attributes
    const uriRegex = /([a-zA-Z][a-zA-Z0-9_:.\-]*)\s*=\s*"([^"]*)"/g;
    let match: RegExpExecArray | null;
    while ((match = uriRegex.exec(processedXml)) !== null) {
        const [, name, value] = match;
        if (value.startsWith(NAMESPACE_ANDROID_10)) {
            processedXml = processedXml.replace(
                new RegExp(`${name}\\s*=\\s*"${value}"`, 'g'),
                `${name}="${NAMESPACE_ANDROID}${value.slice(NAMESPACE_ANDROID_10.length)}"`
            );
        }
    }
    
    return readAxmlElement(processedXml) || [];
}

function parseAndroidManifest(
    xml: string,
    attributes: Record<string, string>
): {
    package_name?: string;
    versionName?: string;
    versionCode?: number | null;
    minSdkVersion?: number | null;
    targetSdkVersion?: number | null;
    mainActivity?: string;
} {
    const result: any = {};
    
    // Extract common attributes
    if (attributes['package']) {
        result.package_name = attributes['package'];
    }
    
    if (attributes['versionName']) {
        result.versionName = attributes['versionName'];
    }
    
    if (attributes['versionCode']) {
        result.versionCode = parseInt(attributes['versionCode'], 10) || null;
    }
    
    if (attributes['minSdkVersion']) {
        result.minSdkVersion = parseInt(attributes['minSdkVersion'], 10) || null;
    }
    
    if (attributes['targetSdkVersion']) {
        result.targetSdkVersion = parseInt(attributes['targetSdkVersion'], 10) || null;
    }
    
    // Find main activity from launcher intent-filter
    const activities: AxmlElement[] = [];
    let inLauncherActivity = false;
    let currentActivity: AxmlElement | null = null;
    
    function processActivity(element: AxmlElement, parent: any) {
        if (element.tag === 'activity') {
            const activityAttrs: Record<string, string> = {};
            
            // Collect attributes from all levels
            let attrsStack: Record<string, string>[] = [attributes];
            for (const child of element.children || []) {
                if (child.attributes) {
                    attrsStack.push(child.attributes);
                }
            }
            
            while (attrsStack.length > 0) {
                const levelAttrs = attrsStack.pop()!;
                Object.assign(activityAttrs, levelAttrs);
            }
            
            // Check for launcher intent-filter
            let isLauncher = false;
            if (activityAttrs['name']?.includes('.MainActivity')) {
                isLauncher = true;
            }
            
            // Look for explicit launcher flag in intent-filter
            const intentFilter: AxmlElement | null = element.children?.find(
                (c: any) => c.tag === 'intent-filter'
            );
            
            if (intentFilter) {
                let hasLauncherFlag = false;
                
                function checkIntentFilterAttrs(element: AxmlElement, parent: any) {
                    if (element.attributes && element.attributes['android:priority'] !== undefined) {
                        const priority = parseInt(element.attributes['android:priority'], 10);
                        // Priority 999 or higher indicates launcher activity
                        if (priority >= 999 || (parent.tag === 'activity' && parent.attributes?.name)) {
                            hasLauncherFlag = true;
                        }
                    }
                    
                    for (const child of element.children || []) {
                        checkIntentFilterAttrs(child, element);
                    }
                }
                
                checkIntentFilterAttrs(intentFilter, activityAttrs);
            }
            
            if (!isLauncher && !hasLauncherFlag) {
                // Check if this is the only activity or has no other activities
                const allActivities = [];
                function collectAllActivities(element: AxmlElement) {
                    for (const child of element.children || []) {
                        if (child.tag === 'activity') {
                            allActivities.push(child);
                        } else if (child.children) {
                            collectAllActivities(child);
                        }
                    }
                }
                
                collectAllActivities(element);
                isLauncher = allActivities.length <= 1;
            }
            
            if (isLauncher) {
                result.mainActivity = activityAttrs['name'];
            }
        } else if (element.tag === 'activity') {
            activities.push(element);
        }
    }
    
    for (const element of parseAxml(xml)) {
        processActivity(element, attributes);
    }
    
    return result;
}

function parseDexHeader(buffer: Buffer): DexInfo | null {
    const magic = readUInt32LE(buffer, 0);
    if (magic !== DEX_MAGIC) {
        return null;
    }
    
    // Parse header fields
    const headerSize = readUInt16LE(buffer, 4);
    const checksumOffset = readUInt16LE(buffer, 6);
    const checksumSize = readUInt16LE(buffer, 8);
    const linkSize = readUInt16LE(buffer, 10);
    const linkOffset = readUInt16LE(buffer