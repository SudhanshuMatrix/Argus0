// Package enricher provides process and container metadata lookup for flows
// captured by the eBPF program. It reads from the Linux /proc filesystem —
// no additional dependencies required.
package enricher

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ProcessInfo holds the metadata extracted for a given PID.
type ProcessInfo struct {
	PID         uint32
	Name        string // From /proc/<pid>/comm — executable name, max 15 chars
	ContainerID string // From /proc/<pid>/cgroup — extracted Docker/k8s container ID
}

// cacheEntry wraps a ProcessInfo with a timestamp for TTL-based invalidation.
type cacheEntry struct {
	info      ProcessInfo
	expiresAt time.Time
}

// ProcessEnricher caches process metadata lookups to avoid hammering /proc on
// every BPF map iteration. The cache has a short TTL (default 30s) because
// PIDs are reused by the OS relatively quickly.
type ProcessEnricher struct {
	mu       sync.RWMutex
	cache    map[uint32]cacheEntry
	cacheTTL time.Duration
	log      *logrus.Logger
}

// NewProcessEnricher creates a ProcessEnricher with the given cache TTL.
// A TTL of 30 seconds is a good default for most environments.
func NewProcessEnricher(cacheTTL time.Duration, log *logrus.Logger) *ProcessEnricher {
	return &ProcessEnricher{
		cache:    make(map[uint32]cacheEntry),
		cacheTTL: cacheTTL,
		log:      log,
	}
}

// Enrich returns process metadata for the given PID. Results are cached.
// Returns an error if the process no longer exists (/proc/<pid> is missing).
func (e *ProcessEnricher) Enrich(pid uint32) (ProcessInfo, error) {
	// Check cache (read lock is sufficient here).
	e.mu.RLock()
	entry, ok := e.cache[pid]
	e.mu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.info, nil
	}

	// Cache miss or expired — look up from /proc.
	info, err := e.lookupProc(pid)
	if err != nil {
		return ProcessInfo{}, err
	}

	// Write to cache.
	e.mu.Lock()
	e.cache[pid] = cacheEntry{
		info:      info,
		expiresAt: time.Now().Add(e.cacheTTL),
	}
	e.mu.Unlock()

	return info, nil
}

// lookupProc reads /proc/<pid>/comm and /proc/<pid>/cgroup to build a
// ProcessInfo. It is intentionally tolerant: if the cgroup file is missing
// (process not in a container), ContainerID is left empty.
func (e *ProcessEnricher) lookupProc(pid uint32) (ProcessInfo, error) {
	info := ProcessInfo{PID: pid}

	// --- /proc/<pid>/comm ---
	// Contains the executable name, trimmed to 15 characters by the kernel.
	// Example: "nginx\n"
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	commBytes, err := os.ReadFile(commPath)
	if err != nil {
		// ENOENT means the process has exited. Return the error so the caller
		// can decide whether to log a warning or silently skip.
		return ProcessInfo{}, fmt.Errorf("reading %s: %w", commPath, err)
	}
	info.Name = strings.TrimSpace(string(commBytes))

	// --- /proc/<pid>/cgroup ---
	// Parses the cgroup hierarchy to extract a container ID.
	// Container runtimes (Docker, containerd) place the container ID as a
	// 64-character hex string in the cgroup path. We look for it in the form:
	//   .../docker/<64hexchars>
	//   .../kubepods/.../<64hexchars>
	//   .../<64hexchars>.scope
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	containerID, err := extractContainerID(cgroupPath)
	if err != nil {
		// Non-fatal: many processes run outside containers.
		e.log.WithFields(logrus.Fields{
			"pid":  pid,
			"path": cgroupPath,
		}).Trace("Could not extract container ID from cgroup")
	} else {
		info.ContainerID = containerID
	}

	return info, nil
}

// extractContainerID reads /proc/<pid>/cgroup and returns the container ID
// if one is found in the path. Returns an empty string + error if not found.
//
// Cgroup v1 example line:
//   12:devices:/docker/3f4c2b1a9e7d...64chars.../
// Cgroup v2 example line (unified hierarchy):
//   0::/system.slice/docker-3f4c2b1a9e7d...64chars....scope
func extractContainerID(cgroupPath string) (string, error) {
	file, err := os.Open(cgroupPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Split on '/' and look for a 64-character hex token.
		parts := strings.Split(line, "/")
		for _, part := range parts {
			// Strip .scope suffix (cgroup v2 naming)
			part = strings.TrimSuffix(part, ".scope")
			// Docker prefixes with "docker-"
			part = strings.TrimPrefix(part, "docker-")
			// containerd uses the bare container ID
			if isContainerID(part) {
				return part, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scanning %s: %w", cgroupPath, err)
	}

	return "", fmt.Errorf("no container ID found in %s", cgroupPath)
}

// isContainerID returns true if s looks like a 64-character lowercase hex
// string — the format used by Docker and containerd for container IDs.
func isContainerID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// PurgeExpired removes stale entries from the cache. Call this periodically
// (e.g., every minute) to prevent unbounded memory growth. In practice, the
// map will contain at most a few thousand entries on a busy host.
func (e *ProcessEnricher) PurgeExpired() {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	for pid, entry := range e.cache {
		if now.After(entry.expiresAt) {
			delete(e.cache, pid)
		}
	}
}
