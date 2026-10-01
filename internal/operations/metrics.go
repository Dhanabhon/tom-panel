// Package operations implements TomPanel's read-only server observability
// and guarded service actions.
package operations

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Snapshot is one instantaneous observation of server health. No time series
// are stored.
type Snapshot struct {
	CPUPercent   float64 `json:"cpu_percent"`
	Load1        float64 `json:"load_1"`
	Load5        float64 `json:"load_5"`
	Load15       float64 `json:"load_15"`
	MemoryUsedMB int     `json:"memory_used_mb"`
	MemoryTotalMB int    `json:"memory_total_mb"`
	SwapUsedMB   int     `json:"swap_used_mb"`
	SwapTotalMB  int     `json:"swap_total_mb"`
	DiskUsedGB   float64 `json:"disk_used_gb"`
	DiskTotalGB  float64 `json:"disk_total_gb"`
	UptimeHours  float64 `json:"uptime_hours"`
	CollectedAt  time.Time `json:"collected_at"`
}

// ReadSnapshot samples procfs and the state volume. stateRoot tails the disk
// figure to the volume that holds panel state.
func ReadSnapshot(procRoot, stateRoot string) (Snapshot, error) {
	snapshot := Snapshot{CollectedAt: time.Now().UTC()}
	load, err := readLoadAvg(procRoot + "/loadavg")
	if err == nil {
		snapshot.Load1, snapshot.Load5, snapshot.Load15 = load[0], load[1], load[2]
	}
	memory, err := readMemInfo(procRoot + "/meminfo")
	if err == nil {
		snapshot.MemoryTotalMB = memory["MemTotal"]
		snapshot.MemoryUsedMB = memory["MemTotal"] - memory["MemAvailable"]
		snapshot.SwapTotalMB = memory["SwapTotal"]
		snapshot.SwapUsedMB = memory["SwapTotal"] - memory["SwapFree"]
	}
	if cpu, err := readCPU(procRoot + "/stat"); err == nil {
		snapshot.CPUPercent = cpu
	}
	if uptime, err := readUptime(procRoot + "/uptime"); err == nil {
		snapshot.UptimeHours = uptime / 3600
	}
	var stat syscall.Statfs_t
	if err := statfsExisting(stateRoot, &stat); err == nil && stat.Bsize > 0 {
		blockSize := uint64(stat.Bsize)
		total := stat.Blocks * blockSize
		used := (stat.Blocks - stat.Bfree) * blockSize
		snapshot.DiskTotalGB = float64(total) / (1 << 30)
		snapshot.DiskUsedGB = float64(used) / (1 << 30)
	}
	if snapshot.MemoryTotalMB == 0 && snapshot.DiskTotalGB == 0 {
		return snapshot, errors.New("no metrics could be read")
	}
	return snapshot, nil
}

func readLoadAvg(path string) ([3]float64, error) {
	var result [3]float64
	content, err := os.ReadFile(path)
	if err != nil {
		return result, err
	}
	fields := strings.Fields(string(content))
	if len(fields) < 3 {
		return result, fmt.Errorf("malformed loadavg")
	}
	for index := 0; index < 3; index++ {
		value, err := strconv.ParseFloat(fields[index], 64)
		if err != nil {
			return result, err
		}
		result[index] = value
	}
	return result, nil
}

func readMemInfo(path string) (map[string]int, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	result := map[string]int{}
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.Atoi(strings.TrimSuffix(fields[1], "kB"))
		if err != nil {
			continue
		}
		result[strings.TrimSuffix(fields[0], ":")] = value / 1024
	}
	return result, scanner.Err()
}

func readCPU(path string) (float64, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	line := ""
	for _, candidate := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(candidate, "cpu ") {
			line = candidate
			break
		}
	}
	if line == "" {
		return 0, fmt.Errorf("cpu aggregate missing")
	}
	fields := strings.Fields(line)[1:]
	if len(fields) < 5 {
		return 0, fmt.Errorf("cpu aggregate malformed")
	}
	var total, idle float64
	for index, field := range fields {
		value, err := strconv.ParseFloat(field, 64)
		if err != nil {
			return 0, err
		}
		total += value
		if index == 3 || index == 4 {
			idle += value
		}
	}
	if total == 0 {
		return 0, fmt.Errorf("cpu counters empty")
	}
	return 100 * (total - idle) / total, nil
}

func readUptime(path string) (float64, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(content))
	if len(fields) == 0 {
		return 0, fmt.Errorf("uptime malformed")
	}
	return strconv.ParseFloat(fields[0], 64)
}

func statfsExisting(path string, stat *syscall.Statfs_t) error {
	for {
		if err := syscall.Statfs(path, stat); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return os.ErrNotExist
		}
		path = parent
	}
}
