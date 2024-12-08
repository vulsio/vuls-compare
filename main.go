package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/detector"
	"github.com/future-architect/vuls/models"
	"github.com/google/go-cmp/cmp"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) != 4 {
		slog.Error("Exactly three arguments required", "args", os.Args)
		os.Exit(1)
	}

	configPath := os.Args[1]
	scannedPath := os.Args[2]
	goldenPath := os.Args[3]

	err := compare(configPath, scannedPath, goldenPath)
	if err != nil {
		slog.Error("compare", slog.Any("err", err))
		os.Exit(1)
	}
}

func compare(configPath, scannedPath, goldenPath string) error {
	tempdir, err := os.MkdirTemp("", "vuls-compare-*")
	if err != nil {
		return fmt.Errorf("mkdir temp. err: %w", err)
	}
	defer os.RemoveAll(tempdir)

	if err := config.Load(configPath); err != nil {
		return fmt.Errorf("config load. err: %w", err)
	}

	bs, err := os.ReadFile(scannedPath)
	if err != nil {
		return fmt.Errorf("readfile. err: %w", err)
	}
	inputPath := filepath.Join(tempdir, filepath.Base(scannedPath))
	if err := os.WriteFile(inputPath, bs, 0666); err != nil {
		return fmt.Errorf("write file. err: %w", err)
	}
	var r models.ScanResult
	json.Unmarshal(bs, &r)
	rs, err := detector.Detect([]models.ScanResult{r}, tempdir)
	if err != nil {
		return fmt.Errorf("detect. err: %w", err)
	}

	// fmt.Printf("===== rs[0].ScannedCves ======\n")
	// for cveId, vi := range rs[0].ScannedCves {
	// 	fmt.Printf("CVE ID: %s\n", cveId)
	// 	for ccType := range vi.CveContents {
	// 		fmt.Printf("    ccType: %s\n", ccType)
	// 	}
	// }
	// fmt.Printf("==============================\n")

	if err := compareResult(rs[0], goldenPath); err != nil {
		return fmt.Errorf("compare result. err: %w", err)
	}
	return nil
}

func compareResult(got models.ScanResult, goldenPath string) error {
	bs, err := os.ReadFile(goldenPath)
	if err != nil {
		return fmt.Errorf("readfile. err: %w", err)
	}

	var golden models.ScanResult
	if err := json.Unmarshal(bs, &golden); err != nil {
		return fmt.Errorf("unmarshal. err: %w", err)
	}

	ccType := models.NewCveContentType(golden.Family)
	if diff := cmp.Diff(filter(golden, ccType), filter(got, ccType)); diff != "" {
		slog.Error("diff found")
		fmt.Printf("======== [-expected +got] =========\n")
		fmt.Printf("%s\n", diff)
	}

	return nil
}

func filter(r models.ScanResult, ccType models.CveContentType) models.VulnInfos {
	for cveId, vi := range r.ScannedCves {
		switch r.Family {
		case constant.Alma, constant.Rocky:
			noneFixed := func() bool {
				for _, p := range vi.AffectedPackages {
					if !p.NotFixedYet {
						return false
					}
				}
				return true
			}()
			if noneFixed {
				delete(r.ScannedCves, cveId)
				continue
			}
		}
		ccs, found := vi.CveContents[ccType]
		if found {
			// slog.Info("found", "cc", cc)
			for i, cc := range ccs {
				cc.Published = time.Time{}
				ccs[i] = cc
			}
			vi.CveContents = models.CveContents{ccType: ccs}
		} else {
			// slog.Info("not found", "ccs", r)
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
