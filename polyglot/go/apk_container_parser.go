package main

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// APK represents the parsed Android package structure.
type APK struct {
	Name        string
	Version     string
	PackageName string
	Manifest    *ManifestInfo
	Permissions []string
	Certificates []*x509.Certificate
	NativeLibs  []string
	Assets      []AssetInfo
	Resources   ResourceSummary
}

// ManifestInfo holds parsed manifest data.
type ManifestInfo struct {
	PackageName string
	VersionCode int32
	VersionName string
	MinSDK      int32
	TargetSDK   int32
	Exported    bool
}

// AssetInfo represents an extracted asset file.
type AssetInfo struct {
	Name     string
	Size     int64
	Path     string
	IsBinary bool
}

// ResourceSummary holds ARSC parsing results.
type ResourceSummary struct {
	TableSize   uint32
	ResourceCount uint32
	TypeCount    uint32
}

// Reader is a flexible interface for APK input sources.
type Reader interface {
	io.ReaderAt
	io.Seeker
}

// DefaultReader wraps an os.File.
func NewDefaultReader(path string) (Reader, error) {
	return os.Open(path)
}

// BytesReader creates a reader from byte slice.
func NewBytesReader(data []byte) Reader {
	return bytes.NewReader(data)
}

// APKParser handles the complete parsing pipeline.
type APKParser struct {
	Source    Reader
	APK       *APK
	Verbose   bool
}

// NewAPKParser creates a new parser instance.
func NewAPKParser(source Reader, verbose bool) *APKParser {
	return &APKParser{
		Source:  source,
		APK:     &APK{},
		Verbose: verbose,
	}
}

// Parse executes the complete APK analysis pipeline.
func (p *APKParser) Parse() error {
	if err := p.parseContainer(); err != nil {
		return fmt.Errorf("container parse failed: %w", err)
	}
	if err := p.parseManifest(); err != nil {
		return fmt.Errorf("manifest parse failed: %w", err)
	}
	p.extractCertificates()
	p.scanNativeLibs()
	p.analyzeAssets()
	return nil
}

// parseContainer extracts the APK metadata from ZIP structure.
func (p *APKParser) parseContainer() error {
	r, ok := p.Source.(io.ReaderAt)
	if !ok {
		return fmt.Errorf("source must be io.ReaderAt")
	}

	zr, err := zip.OpenReader(r)
	if err != nil {
		return fmt.Errorf("open ZIP: %w", err)
	}
	defer zr.Close()

	p.APK.Name = filepath.Base(zr.Name)

	for _, file := range zr.File {
		switch file.Name {
		case "AndroidManifest.xml":
			p.parseContainerFile(file, func(data []byte) error {
				var m ManifestInfo
				if err := xml.Unmarshal(data, &m); err != nil {
					return fmt.Errorf("unmarshal manifest: %w", err)
				}
				p.APK.Manifest = &m
				return nil
			})
		case "classes.dex":
			p.parseContainerFile(file, func(data []byte) error {
				p.APK.NativeLibs = append(p.APK.NativeLibs, file.Name)
				return nil
			})
		case "lib/armeabi-v7a/libfoo.so", "lib/arm64-v8a/libbar.so":
			p.parseContainerFile(file, func(data []byte) error {
				p.APK.NativeLibs = append(p.APK.NativeLibs, file.Name)
				return nil
			})
		case "META-INF/*.RSA", "META-INF/*.DSA", "META-INF/*.SF":
			p.parseContainerFile(file, func(data []byte) error {
				if strings.HasSuffix(file.Name, ".RSA") || strings.HasSuffix(file.Name, ".DSA") {
					cert, err := x509.ParseCertificate(data)
					if err == nil {
						p.APK.Certificates = append(p.APK.Certificates, cert)
					}
				}
				return nil
			})
		case "assets/keystore/*":
			p.parseContainerFile(file, func(data []byte) error {
				cert, err := x509.ParseCertificate(data)
				if err == nil {
					p.APK.Certificates = append(p.APK.Certificates, cert)
				}
				return nil
			})
		case "assets/*":
			p.parseContainerFile(file, func(data []byte) error {
				info := AssetInfo{
					Name:  file.Name,
					Size:  file.UncompressedSize64,
					Path:  filepath.Join("assets", file.Name),
					Binary: isBinaryData(data[:min(1024, len(data))]),
				}
				p.APK.Assets = append(p.APK.Assets, info)
				return nil
			})
		case "res/values/strings.xml":
			p.parseContainerFile(file, func(data []byte) error {
				var s struct {
					Resources struct {
						Strings struct {
							Items []struct {
								Name  string `xml:"name"`
								Value string `xml:",chardata"`
							} `xml:"item"`
						} `xml:"resources > strings > item"`
					} `xml:"resources"`
				}
				if err := xml.Unmarshal(data, &s); err == nil {
					p.APK.Resources.TableSize = 1024 // placeholder for ARSC
					for _, i := range s.Resources.Strings.Items {
						fmt.Printf("String resource: %s = %q\n", i.Name, i.Value)
					}
				}
				return nil
			})
		case "res/":
			p.parseContainerFile(file, func(data []byte) error {
				if strings.HasSuffix(file.Name, ".xml") && !strings.Contains(file.Name, "values/") {
					fmt.Printf("Source XML: %s\n", file.Name)
				}
				return nil
			})
		}
	}

	p.APK.Resources.TypeCount = 1 // placeholder for ARSC type count
	p.APK.Resources.ResourceCount = uint32(len(zr.File))

	return nil
}

// parseContainerFile reads and processes a container file.
func (p *APKParser) parseContainerFile(file *zip.File, processor func([]byte) error) error {
	data, err := file.Open()
	if err != nil {
		return fmt.Errorf("open %s: %w", file.Name, err)
	}
	defer data.Close()

	size := file.UncompressedSize64
	if size == 0 {
		size = file.CompressedSize64
	}

	buf := make([]byte, min(8192, int(size)))
	n, _ := io.ReadFull(data, buf)
	data.Reset() // reuse buffer for processor

	if err := processor(buf[:n]); err != nil {
		return fmt.Errorf("process %s: %w", file.Name, err)
	}

	return nil
}

// parseManifest extracts detailed manifest information.
func (p *APKParser) parseManifest() error {
	if p.APK.Manifest == nil {
		return nil
	}

	manifest := p.APK.Manifest

	// Parse version code/name from package element attributes
	parts := strings.SplitN(manifest.PackageName, "/", 2)
	p.APK.PackageName = parts[0]

	// Extract min/target SDK from uses-sdk
	if manifest.MinSDK > 0 {
		fmt.Printf("Min SDK: %d\n", manifest.MinSDK)
	}
	if manifest.TargetSDK > 0 {
		fmt.Printf("Target SDK: %d\n", manifest.TargetSDK)
	}

	return nil
}

// extractCertificates scans for additional certificate sources.
func (p *APKParser) extractCertificates() {
	for _, cert := range p.APK.Certificates {
		if cert != nil {
			fmt.Printf("Certificate found: %s, Issuer: %s\n",
				cert.Subject.CommonName, cert.Issuer.CommonName)
		}
	}
}

// scanNativeLibs identifies native libraries.
func (p *APKParser) scanNativeLibs() {
	for _, lib := range p.APK.NativeLibs {
		if strings.HasSuffix(lib, ".so") || strings.Contains(lib, "lib") {
			fmt.Printf("Native library: %s\n", lib)
		}
	}
}

// analyzeAssets performs asset-level analysis.
func (p *APKParser) analyzeAssets() {
	for _, a := range p.APK.Assets {
		if a.Binary {
			fmt.Printf("Binary asset detected: %s (%d bytes)\n", a.Name, a.Size)
		}
	}
}

// isBinaryData checks if data appears to be binary.
func isBinaryData(data []byte) bool {
	for _, b := range data {
		if b < 32 && b != 9 && b != 10 && b != 13 { // skip common whitespace
			return true
		}
	}
	return false
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// APKScanner is a high-level scanner for quick analysis.
type APKScanner struct {
	Path string
	Verbose bool
}

// NewAPKScanner creates a new scanner instance.
func NewAPKScanner(path string, verbose bool) *APKScanner {
	return &APKScanner{Path: path, Verbose: verbose}
}

// Scan performs the complete analysis pipeline.
func (s *APKScanner) Scan() (*APK, error) {
	reader, err := NewDefaultReader(s.Path)
	if err != nil {
		return nil, fmt.Errorf("open APK file: %w", err)
	}
	defer reader.Close()

	parser := NewAPKParser(reader, s.Verbose)
	if err := parser.Parse(); err != nil {
		return nil, fmt.Errorf("parse APK: %w", err)
	}

	return parser.APK, nil
}

// PrintReport outputs a formatted analysis report.
func (s *APKScanner) PrintReport(apk *APK) {
	fmt.Printf("\n=== APK Probe Report ===\n")
	fmt.Printf("File: %s\n", apk.Name)
	if apk.Manifest != nil {
		fmt.Printf("Package: %s\n", apk.PackageName)
		fmt.Printf("Version Code: %d, Name: %q\n", apk.Manifest.VersionCode, apk.Manifest.VersionName)
	}
	fmt.Printf("Certificates: %d\n", len(apk.Certificates))
	fmt.Printf("Native Libraries: %d\n", len(apk.NativeLibs))
	fmt.Printf("Assets: %d\n", len(apk.Assets))
	fmt.Printf("Resources (ARSC): TableSize=%d, Types=%d\n", apk.Resources.TableSize, apk.Resources.TypeCount)

	if len(apk.Certificates) > 0 {
		for i, cert := range apk.Certificates {
			if cert != nil {
				fmt.Printf("\n--- Certificate %d ---\n", i+1)
				fmt.Printf("Subject: %s\n", cert.Subject.CommonName)
				fmt.Printf("Issuer: %s\n", cert.Issuer.CommonName)
				fmt.Printf("Valid From: %s, To: %s\n", cert.NotBefore, cert.NotAfter)
			}
		}
	}

	if len(apk.NativeLibs) > 0 {
		fmt.Println("\n--- Native Libraries ---")
		for _, lib := range apk.NativeLibs {
			fmt.Printf("  %s\n", lib)
		}
	}

	if len(apk.Assets) > 0 {
		fmt.Println("\n--- Assets (Binary Only) ---")
		for _, a := range apk.Assets {
			if a.Binary {
				fmt.Printf("  %s (%d bytes)\n", a.Name, a.Size)
			}
		}
	}

	fmt.Println("========================\n")
}

// CLI interface for command-line usage.
func RunCLI(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: apkprobe <apk-file> [--verbose]")
		return 1
	}

	path := args[0]
	verbose := false
	for i := 1; i < len(args); i++ {
		if args[i] == "--verbose" || args[i] == "-v" {
			verbose = true
		}
	}

	scanner := NewAPKScanner(path, verbose)
	apk, err := scanner.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	scanner.PrintReport(apk)
	return 0
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: apkprobe <apk-file> [--verbose]")
		os.Exit(1)
	}

	exitCode := RunCLI(os.Args[1:])
	os.Exit(exitCode)
}