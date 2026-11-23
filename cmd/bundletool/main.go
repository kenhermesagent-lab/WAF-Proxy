// Command bundletool produces the signed manifest a bundle channel serves.
//
//	bundletool keygen -out publisher.key
//	bundletool sign -dir packs -seq 42 -key publisher.key -base /packs/ -out manifest.json
//
// A pack file is the JSON documented in internal/bundle (bundle, version,
// rules). The tool validates and compiles every rule before it signs anything,
// so a publisher cannot ship a pack the WAF will reject at install time.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/bundle"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundletool:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  bundletool keygen -out publisher.key
  bundletool sign -dir packs -seq N -key publisher.key [-base /packs/] [-out manifest.json]`)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file to write the private key to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	priv, err := bundle.GenerateKey()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(bundle.PrivateKeyHex(priv)+"\n"), 0o600); err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("private key: %s\npublic key:  %s\n", *out, hex.EncodeToString(pub))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	dir := fs.String("dir", "", "directory of pack files")
	seq := fs.Int64("seq", 0, "manifest sequence, larger than every previous one")
	keyFile := fs.String("key", "", "ed25519 private key file")
	base := fs.String("base", "", "URL prefix for pack paths")
	out := fs.String("out", "manifest.json", "manifest file to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *keyFile == "" || *seq <= 0 {
		return fmt.Errorf("-dir, -seq and -key are required")
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	priv, err := bundle.ParsePrivateKey(string(raw))
	if err != nil {
		return err
	}

	files, err := filepath.Glob(filepath.Join(*dir, "*.json"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no pack files in %s", *dir)
	}
	sort.Strings(files)
	manifest := bundle.Manifest{Sequence: *seq}
	seen := map[string]bool{}
	outName := filepath.Base(*out)
	for _, file := range files {
		// A manifest written into the pack directory is not a pack, and a
		// second run would otherwise fail on it.
		if filepath.Base(file) == outName {
			continue
		}
		body, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		var pack bundle.Pack
		if err := json.Unmarshal(body, &pack); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		if err := waf.ValidateBundle(waf.Bundle{Name: pack.Bundle, Version: pack.Version, Rules: pack.Rules}); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		if err := waf.ValidateCompile(pack.Bundle, pack.Rules); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		if seen[pack.Bundle] {
			return fmt.Errorf("%s: bundle %s appears in more than one pack file", file, pack.Bundle)
		}
		seen[pack.Bundle] = true
		sum := sha256.Sum256(body)
		manifest.Bundles = append(manifest.Bundles, bundle.Ref{
			Name: pack.Bundle, Version: pack.Version, Rules: len(pack.Rules),
			Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]),
			Path: strings.TrimSuffix(*base, "/") + "/" + filepath.Base(file),
		})
	}

	signed, err := bundle.SignManifest(manifest, priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, signed, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %d bundle(s) into %s\n", len(manifest.Bundles), *out)
	return nil
}
