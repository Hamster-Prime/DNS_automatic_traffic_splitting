package querylog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type LogEntry struct {
	ID            int64          `json:"id"`
	Time          time.Time      `json:"time"`
	ClientIP      string         `json:"client_ip"`
	DownstreamECS string         `json:"downstream_ecs,omitempty"`
	Domain        string         `json:"domain"`
	Type          string         `json:"type"`
	Upstream      string         `json:"upstream"`
	Answer        string         `json:"answer"`
	AnswerRecords []AnswerRecord `json:"answer_records"`
	DurationMs    int64          `json:"duration_ms"`
	Status        string         `json:"status"`
}

type AnswerRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  uint32 `json:"ttl"`
}

type Stats struct {
	StartTime     time.Time        `json:"start_time"`
	TotalQueries  int64            `json:"total_queries"`
	TotalCN       int64            `json:"total_cn"`
	TotalOverseas int64            `json:"total_overseas"`
	QPS           float64          `json:"qps"`
	TopClients    map[string]int64 `json:"top_clients"`
	TopDomains    map[string]int64 `json:"top_domains"`
}

type QueryLogger struct {
	mu         sync.RWMutex
	fileMu     sync.Mutex
	enabled    bool
	logs       []*LogEntry
	maxSizeMB  int
	maxHistory int
	nextID     int64
	filePath   string
	saveToFile bool
	recentLogs []time.Time
	stats      Stats

	persistedLogCount int64
}

const defaultMaxMemoryLogs = 5000
const qpsWindow = 10 * time.Second

func NewQueryLogger(enabled bool, maxHistory, maxSizeMB int, filePath string, saveToFile bool) *QueryLogger {
	if maxSizeMB <= 0 {
		maxSizeMB = 1
	}
	if maxHistory <= 0 {
		maxHistory = defaultMaxMemoryLogs
	}
	if !enabled {
		saveToFile = false
		filePath = ""
	}

	l := &QueryLogger{
		enabled:    enabled,
		logs:       make([]*LogEntry, 0, maxHistory),
		maxSizeMB:  maxSizeMB,
		maxHistory: maxHistory,
		nextID:     1,
		filePath:   filePath,
		saveToFile: saveToFile,
		stats: Stats{
			StartTime:  time.Now(),
			TopClients: make(map[string]int64),
			TopDomains: make(map[string]int64),
		},
	}

	if enabled && saveToFile && filePath != "" {
		l.restoreStatsFromFile()
	}

	return l
}

func (l *QueryLogger) restoreStatsFromFile() {
	f, err := os.Open(l.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Error opening log file for stats restoration: %v", err)
		}
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		atomic.AddInt64(&l.persistedLogCount, 1)

		var entry LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			l.updateTotals(&entry)
			if entry.ID >= l.nextID {
				l.nextID = entry.ID + 1
			}
		}
	}
}

func (l *QueryLogger) AddLog(entry *LogEntry) {
	if !l.enabled {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry.ID = l.nextID
	l.nextID++
	if entry.Time.IsZero() {
		entry.Time = time.Now()
	}

	l.recordRecentLog(entry.Time)
	l.updateTotals(entry)
	l.addToMemory(entry)

	if l.saveToFile && l.filePath != "" {
		go l.appendToFile(*entry)
	}
}

func (l *QueryLogger) updateTotals(entry *LogEntry) {
	l.stats.TotalQueries++
	if strings.Contains(entry.Upstream, "CN") {
		l.stats.TotalCN++
	} else if strings.Contains(entry.Upstream, "Overseas") {
		l.stats.TotalOverseas++
	}
}

func (l *QueryLogger) addToMemory(entry *LogEntry) {
	l.logs = append(l.logs, entry)
	l.stats.TopClients[entry.ClientIP]++
	l.stats.TopDomains[entry.Domain]++

	if len(l.logs) > l.maxHistory {
		evicted := l.logs[0]
		l.logs = l.logs[1:]
		l.decrementTopCounters(evicted)
	}
}

func (l *QueryLogger) decrementTopCounters(entry *LogEntry) {
	if entry == nil {
		return
	}

	if count := l.stats.TopClients[entry.ClientIP] - 1; count > 0 {
		l.stats.TopClients[entry.ClientIP] = count
	} else {
		delete(l.stats.TopClients, entry.ClientIP)
	}

	if count := l.stats.TopDomains[entry.Domain] - 1; count > 0 {
		l.stats.TopDomains[entry.Domain] = count
	} else {
		delete(l.stats.TopDomains, entry.Domain)
	}
}

func (l *QueryLogger) recordRecentLog(ts time.Time) {
	l.recentLogs = append(l.recentLogs, ts)

	cutoff := ts.Add(-qpsWindow)
	firstValid := 0
	for firstValid < len(l.recentLogs) && l.recentLogs[firstValid].Before(cutoff) {
		firstValid++
	}
	if firstValid > 0 {
		l.recentLogs = l.recentLogs[firstValid:]
	}
}

func (l *QueryLogger) appendToFile(entry LogEntry) {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	limitBytes := int64(l.maxSizeMB) * 1024 * 1024

	fi, err := os.Stat(l.filePath)
	if err == nil {
		if fi.Size()+int64(len(data)) > limitBytes {
			remainingLines, err := l.pruneLogFile(limitBytes)
			if err != nil {
				log.Printf("Error pruning log file: %v", err)
			} else {
				atomic.StoreInt64(&l.persistedLogCount, remainingLines)
			}
		}
	} else if !os.IsNotExist(err) {
		log.Printf("Error checking log file size: %v", err)
		return
	}

	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error writing to log file: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		log.Printf("Error writing data to log file: %v", err)
		return
	}

	atomic.AddInt64(&l.persistedLogCount, 1)
}

type countingWriter struct {
	writer io.Writer
	lines  int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.lines += int64(bytes.Count(p[:n], []byte{'\n'}))
	return n, err
}

func (l *QueryLogger) pruneLogFile(limitBytes int64) (int64, error) {
	targetSize := int64(float64(limitBytes) * 0.8)

	f, err := os.Open(l.filePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	fileSize := fi.Size()

	if fileSize <= targetSize {
		return atomic.LoadInt64(&l.persistedLogCount), nil
	}

	startPos := fileSize - targetSize
	dir := filepath.Dir(l.filePath)
	tmpFile, err := os.CreateTemp(dir, "querylog_*.tmp")
	if err != nil {
		return 0, err
	}
	tmpName := tmpFile.Name()

	defer func() {
		if tmpFile != nil {
			tmpFile.Close()
		}
		if err != nil {
			os.Remove(tmpName)
		}
	}()

	if _, err = f.Seek(startPos, 0); err != nil {
		return 0, err
	}

	buf := make([]byte, 1024)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return 0, err
	}

	copyStart := startPos
	newlineIdx := bytes.IndexByte(buf[:n], '\n')
	if newlineIdx != -1 {
		copyStart = startPos + int64(newlineIdx) + 1
	}

	if _, err = f.Seek(copyStart, 0); err != nil {
		return 0, err
	}

	counter := &countingWriter{writer: tmpFile}
	if _, err = io.Copy(counter, f); err != nil {
		return 0, err
	}

	f.Close()
	tmpFile.Close()
	tmpFile = nil

	if err := os.Rename(tmpName, l.filePath); err != nil {
		return 0, err
	}

	return counter.lines, nil
}

func (l *QueryLogger) GetLogs(offset, limit int, search string) ([]*LogEntry, int64) {
	if !l.enabled {
		return nil, 0
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.saveToFile && l.filePath != "" {
		totalHint := int64(-1)
		stopAfter := 0
		if search == "" {
			totalHint = atomic.LoadInt64(&l.persistedLogCount)
			stopAfter = offset + limit
		}

		fileLogs, total, err := l.readLogsFromFileBackwards(offset, limit, search, stopAfter, totalHint)
		if err == nil {
			return fileLogs, total
		}
	}

	if search == "" {
		total := len(l.logs)
		if total == 0 || offset >= total {
			return nil, int64(total)
		}

		result := make([]*LogEntry, 0, min(limit, total-offset))
		for i := total - 1 - offset; i >= 0 && len(result) < limit; i-- {
			result = append(result, l.logs[i])
		}
		return result, int64(total)
	}

	var result []*LogEntry
	var count int64
	searchLower := strings.ToLower(search)

	for i := len(l.logs) - 1; i >= 0; i-- {
		entry := l.logs[i]

		if !matches(entry, searchLower) {
			continue
		}

		if count >= int64(offset) && len(result) < limit {
			result = append(result, entry)
		}
		count++
	}

	return result, count
}

func (l *QueryLogger) readLogsFromFileBackwards(offset, limit int, search string, stopAfter int, totalHint int64) ([]*LogEntry, int64, error) {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()

	file, err := os.Open(l.filePath)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}

	fileSize := stat.Size()
	var result []*LogEntry
	var matchCount int64

	buf := make([]byte, 4096)
	pos := fileSize
	var line []byte

	searchLower := strings.ToLower(search)

	processLine := func(reversed []byte) bool {
		entry := parseReverseLine(reversed)
		if entry == nil || !matches(entry, searchLower) {
			return false
		}

		if matchCount >= int64(offset) && len(result) < limit {
			result = append(result, entry)
		}
		matchCount++

		return stopAfter > 0 && totalHint >= 0 && searchLower == "" && matchCount >= int64(stopAfter)
	}

	for pos > 0 {
		readSize := int64(len(buf))
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize
		if _, err := file.Seek(pos, 0); err != nil {
			break
		}

		n, err := file.Read(buf[:readSize])
		if err != nil {
			break
		}

		for i := n - 1; i >= 0; i-- {
			b := buf[i]
			if b == '\n' {
				if len(line) > 0 {
					if processLine(line) {
						return result, totalHint, nil
					}
					line = line[:0]
				}
			} else {
				line = append(line, b)
			}
		}
	}

	if len(line) > 0 {
		if processLine(line) {
			return result, totalHint, nil
		}
	}

	if totalHint >= 0 && searchLower == "" {
		return result, totalHint, nil
	}

	return result, matchCount, nil
}

func parseReverseLine(reversed []byte) *LogEntry {
	n := len(reversed)
	normal := make([]byte, n)
	for i := 0; i < n; i++ {
		normal[i] = reversed[n-1-i]
	}

	var entry LogEntry
	if err := json.Unmarshal(normal, &entry); err != nil {
		return nil
	}
	return &entry
}

func matches(entry *LogEntry, searchLower string) bool {
	if searchLower == "" {
		return true
	}
	return strings.Contains(strings.ToLower(entry.ClientIP), searchLower) ||
		strings.Contains(strings.ToLower(entry.DownstreamECS), searchLower) ||
		strings.Contains(strings.ToLower(entry.Domain), searchLower) ||
		strings.Contains(strings.ToLower(entry.Type), searchLower) ||
		strings.Contains(strings.ToLower(entry.Upstream), searchLower) ||
		strings.Contains(strings.ToLower(entry.Answer), searchLower) ||
		strings.Contains(strings.ToLower(entry.Status), searchLower)
}

func (l *QueryLogger) GetStats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	s := l.stats
	s.QPS = l.currentQPS(time.Now())
	s.TopClients = make(map[string]int64, len(l.stats.TopClients))
	for k, v := range l.stats.TopClients {
		s.TopClients[k] = v
	}
	s.TopDomains = make(map[string]int64, len(l.stats.TopDomains))
	for k, v := range l.stats.TopDomains {
		s.TopDomains[k] = v
	}

	return s
}

func (l *QueryLogger) currentQPS(now time.Time) float64 {
	if len(l.recentLogs) == 0 {
		return 0
	}

	cutoff := now.Add(-qpsWindow)
	recentCount := 0
	for i := len(l.recentLogs) - 1; i >= 0; i-- {
		if l.recentLogs[i].Before(cutoff) {
			break
		}
		recentCount++
	}

	return float64(recentCount) / qpsWindow.Seconds()
}

func (l *QueryLogger) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logs = make([]*LogEntry, 0, l.maxHistory)
	l.recentLogs = nil
	l.stats.TopClients = make(map[string]int64)
	l.stats.TopDomains = make(map[string]int64)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
