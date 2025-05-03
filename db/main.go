package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector"
	"github.com/future-architect/vuls/models"
	"github.com/google/go-cmp/cmp"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "[usage] go run main.go <scan result path> <before vuls-nightly-db path> <after vuls-nightly-db path>")
		os.Exit(1)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(scanresultPath, beforeDBPath, afterDBPath string) error {
	bs, err := os.ReadFile(scanresultPath)
	if err != nil {
		return fmt.Errorf("read %s. err: %w", scanresultPath, err)
	}

	var r models.ScanResult
	if err := json.Unmarshal(bs, &r); err != nil {
		return fmt.Errorf("unmarshal %s. err: %w", scanresultPath, err)
	}

	config.Conf = config.Config{
		CveDict: config.GoCveDictConf{
			VulnDict: config.VulnDict{
				Type: "sqlite3",
			},
		},
		OvalDict: config.GovalDictConf{
			VulnDict: config.VulnDict{
				Type: "sqlite3",
			},
		},
		Gost: config.GostConf{
			VulnDict: config.VulnDict{
				Type: "sqlite3",
			},
		},
		Exploit: config.ExploitConf{
			VulnDict: config.VulnDict{
				Type: "sqlite3",
			},
		},
		Metasploit: config.MetasploitConf{
			VulnDict: config.VulnDict{
				Type: "sqlite3",
			},
		},
		KEVuln: config.KEVulnConf{
			VulnDict: config.VulnDict{
				Type: "sqlite3",
			},
		},
		Cti: config.CtiConf{
			VulnDict: config.VulnDict{
				Type: "sqlite3",
			},
		},
		ReportOpts: config.ReportOpts{RefreshCve: true},
	}

	beforeDir, err := os.MkdirTemp("", "vuls-compare-*")
	if err != nil {
		return fmt.Errorf("mkdir temp. err: %w", err)
	}
	defer os.RemoveAll(beforeDir)

	bf, err := os.Create(filepath.Join(beforeDir, filepath.Base(scanresultPath)))
	if err != nil {
		return fmt.Errorf("create %s. err: %w", filepath.Join(beforeDir, filepath.Base(scanresultPath)), err)
	}
	defer bf.Close()

	if _, err := bf.Write(bs); err != nil {
		return fmt.Errorf("write %s. err: %w", filepath.Join(beforeDir, filepath.Base(scanresultPath)), err)
	}

	config.Conf.Vuls2 = config.Vuls2Conf{
		Repository: "vuls-nightly-db:latest",
		Path:       beforeDBPath,
		SkipUpdate: true,
	}

	brs, err := detector.Detect([]models.ScanResult{r}, beforeDir)
	if err != nil {
		return fmt.Errorf("before detect. err: %w", err)
	}

	afterDir, err := os.MkdirTemp("", "vuls-compare-*")
	if err != nil {
		return fmt.Errorf("mkdir temp. err: %w", err)
	}
	defer os.RemoveAll(afterDir)

	af, err := os.Create(filepath.Join(afterDir, filepath.Base(scanresultPath)))
	if err != nil {
		return fmt.Errorf("create %s. err: %w", filepath.Join(afterDir, filepath.Base(scanresultPath)), err)
	}
	defer af.Close()

	if _, err := af.Write(bs); err != nil {
		return fmt.Errorf("write %s. err: %w", filepath.Join(afterDBPath, filepath.Base(scanresultPath)), err)
	}

	config.Conf.Vuls2 = config.Vuls2Conf{
		Repository: "vuls-nightly-db:nightly",
		Path:       afterDBPath,
		SkipUpdate: true,
	}

	ars, err := detector.Detect([]models.ScanResult{r}, afterDir)
	if err != nil {
		return fmt.Errorf("after detect. err: %w", err)
	}

	if diff := cmp.Diff(brs[0].ScannedCves, ars[0].ScannedCves); diff != "" {
		if err := os.MkdirAll("diff", 0755); err != nil {
			return fmt.Errorf("mkdir %s. err: %w", "diff", err)
		}

		f, err := os.Create(filepath.Join("diff", "cves.diff"))
		if err != nil {
			return fmt.Errorf("create %s. err: %w", filepath.Join("diff", "cves.diff"), err)
		}
		defer f.Close()

		if _, err := f.WriteString(fmt.Sprintf("======== [-before +after] =========\n%s", diff)); err != nil {
			return fmt.Errorf("write to %s. err: %w", filepath.Join("diff", "cves.diff"), err)
		}

		bf2, err := os.Create(filepath.Join("diff", "before.json"))
		if err != nil {
			return fmt.Errorf("create %s. err: %w", filepath.Join("diff", "before.json"), err)
		}
		defer bf2.Close()

		be := json.NewEncoder(bf2)
		be.SetIndent("", "  ")
		be.SetEscapeHTML(false)
		if err := be.Encode(brs[0]); err != nil {
			return fmt.Errorf("encode to %s. err: %w", filepath.Join("diff", "before.json"), err)
		}

		af2, err := os.Create(filepath.Join("diff", "after.json"))
		if err != nil {
			return fmt.Errorf("create %s. err: %w", filepath.Join("diff", "after.json"), err)
		}
		defer af2.Close()

		ae := json.NewEncoder(af2)
		ae.SetIndent("", "  ")
		ae.SetEscapeHTML(false)
		if err := ae.Encode(ars[0]); err != nil {
			return fmt.Errorf("encode to %s. err: %w", filepath.Join("diff", "after.json"), err)
		}

		return fmt.Errorf("diff found")
	}

	return nil
}
