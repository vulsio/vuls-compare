package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/detector"
	"github.com/future-architect/vuls/models"
	"github.com/google/go-cmp/cmp"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "[usage] go run main.go <scan result path:<results root dir>/<timestamp dir>/<scan result json path>> <before vuls binary path> <before vuls config path> <vuls-nightly-db path>")
		os.Exit(1)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3], os.Args[4]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(scanresultPath, vulsBinaryPath, configPath, vuls2DBPath string) error {
	bs, err := os.ReadFile(scanresultPath)
	if err != nil {
		return fmt.Errorf("read %s. err: %w", scanresultPath, err)
	}

	var r models.ScanResult
	if err := json.Unmarshal(bs, &r); err != nil {
		return fmt.Errorf("unmarshal %s. err: %w", scanresultPath, err)
	}

	beforeDir, err := os.MkdirTemp("", "vuls-compare-*")
	if err != nil {
		return fmt.Errorf("mkdir temp. err: %w", err)
	}
	defer os.RemoveAll(beforeDir)

	if err := os.Mkdir(filepath.Join(beforeDir, filepath.Base(filepath.Dir(scanresultPath))), 0755); err != nil {
		return fmt.Errorf("mkdir %s. err: %w", filepath.Join(beforeDir, filepath.Base(filepath.Dir(scanresultPath))), err)
	}

	bf, err := os.Create(filepath.Join(beforeDir, filepath.Base(filepath.Dir(scanresultPath)), filepath.Base(scanresultPath)))
	if err != nil {
		return fmt.Errorf("create %s. err: %w", filepath.Join(beforeDir, filepath.Base(filepath.Dir(scanresultPath)), filepath.Base(scanresultPath)), err)
	}
	defer bf.Close()

	if _, err := bf.Write(bs); err != nil {
		return fmt.Errorf("write %s. err: %w", filepath.Join(beforeDir, filepath.Base(filepath.Dir(scanresultPath)), filepath.Base(scanresultPath)), err)
	}

	cmd := exec.Command(fmt.Sprintf("./%s", vulsBinaryPath), "report", "--config", configPath, "--results-dir", beforeDir, "--quiet", filepath.Base(filepath.Dir(scanresultPath)))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run %s. err: %w", cmd.String(), err)
	}

	bs, err = os.ReadFile(filepath.Join(beforeDir, filepath.Base(filepath.Dir(scanresultPath)), filepath.Base(scanresultPath)))
	if err != nil {
		return fmt.Errorf("read %s. err: %w", filepath.Join(beforeDir, filepath.Base(filepath.Dir(scanresultPath)), filepath.Base(scanresultPath)), err)
	}
	var br models.ScanResult
	if err := json.Unmarshal(bs, &br); err != nil {
		return fmt.Errorf("decode %s. err: %w", filepath.Join(beforeDir, filepath.Base(scanresultPath)), err)
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
		return fmt.Errorf("write %s. err: %w", filepath.Join(afterDir, filepath.Base(scanresultPath)), err)
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
		Vuls2: config.Vuls2DictConf{
			Repository: "vuls-nightly-db:latest",
			Path:       vuls2DBPath,
			SkipUpdate: true,
		},
	}

	ars, err := detector.Detect([]models.ScanResult{r}, afterDir)
	if err != nil {
		return fmt.Errorf("after detect. err: %w", err)
	}

	if diff := cmp.Diff(filter(br, constant.RedHat), filter(ars[0], constant.RedHat)); diff != "" {
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

		bs, err := os.ReadFile(filepath.Join(beforeDir, filepath.Base(filepath.Dir(scanresultPath)), filepath.Base(scanresultPath)))
		if err != nil {
			return fmt.Errorf("read %s. err: %w", filepath.Join(beforeDir, filepath.Base(filepath.Dir(scanresultPath)), filepath.Base(scanresultPath)), err)
		}
		if _, err := bf2.Write(bs); err != nil {
			return fmt.Errorf("write %s. err: %w", filepath.Join("diff", "before.json"), err)
		}

		af2, err := os.Create(filepath.Join("diff", "after.json"))
		if err != nil {
			return fmt.Errorf("create %s. err: %w", filepath.Join("diff", "after.json"), err)
		}
		defer af2.Close()

		bs, err = os.ReadFile(filepath.Join(filepath.Join(afterDir, filepath.Base(scanresultPath))))
		if err != nil {
			return fmt.Errorf("read %s. err: %w", filepath.Join(afterDir, filepath.Base(scanresultPath)), err)
		}
		if _, err := af2.Write(bs); err != nil {
			return fmt.Errorf("write %s. err: %w", filepath.Join("diff", "after.json"), err)
		}

		return fmt.Errorf("diff found")
	}

	return nil
}

func filter(r models.ScanResult, ccType models.CveContentType) models.VulnInfos {
	for cveId, vi := range r.ScannedCves {
		ccs, found := vi.CveContents[ccType]
		if found {
			for i, cc := range ccs {
				cc.Published = time.Time{}
				cc.Optional = nil
				ccs[i] = cc
			}
			vi.CveContents = models.CveContents{ccType: ccs}
		} else {
			vi.CveContents = models.CveContents{}
		}
		for i, d := range vi.DistroAdvisories {
			d.Issued = time.Time{}
			vi.DistroAdvisories[i] = d
		}
		for i := range vi.KEVs {
			if vi.KEVs[i].VulnCheck == nil {
				continue
			}
			if len(vi.KEVs[i].VulnCheck.XDB) == 0 {
				vi.KEVs[i].VulnCheck.XDB = nil
			}
		}
		r.ScannedCves[cveId] = vi
	}
	return r.ScannedCves
}
