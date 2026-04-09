package manager

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"time"
	_ "time/tzdata"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/querylog"
	"doh-autoproxy/internal/router"
	"doh-autoproxy/internal/server"
	"doh-autoproxy/internal/util"
)

type ServiceManager struct {
	mu     sync.Mutex
	Config *config.Config

	GeoManager  *router.GeoDataManager
	Router      *router.Router
	CertManager *util.CertManager
	QueryLog    *querylog.QueryLogger

	DNSServer  *server.DNSServer
	DoTServer  *server.DoTServer
	DoHServer  *server.DoHServer
	DoQServer  *server.DoQServer
	ACMEServer *http.Server

	stopAutoUpdate chan struct{}
}

func NewServiceManager(initialCfg *config.Config) *ServiceManager {
	return &ServiceManager{
		Config:         initialCfg,
		QueryLog:       querylog.NewQueryLogger(initialCfg.QueryLog.Enabled, initialCfg.QueryLog.MaxHistory, initialCfg.QueryLog.MaxSizeMB, initialCfg.QueryLog.File, initialCfg.QueryLog.SaveToFile),
		stopAutoUpdate: make(chan struct{}),
	}
}

func (m *ServiceManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.startInternal(); err != nil {
		return err
	}
	go m.runAutoUpdate()
	return nil
}

func (m *ServiceManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	select {
	case m.stopAutoUpdate <- struct{}{}:
	default:
	}

	return m.stopInternal()
}

func (m *ServiceManager) Reload(newCfg *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Println("正在重新加载服务配置...")

	geoChanged := m.Config.GeoData.GeoIPDat != newCfg.GeoData.GeoIPDat ||
		m.Config.GeoData.GeoSiteDat != newCfg.GeoData.GeoSiteDat

	if geoChanged {
		log.Println("GeoData 配置已更改，将在重新启动期间重新加载 Geo 数据库。")
		m.GeoManager = nil
		debug.FreeOSMemory()
	} else {
		log.Println("GeoData 配置未更改，保留现有的 Geo 数据库以加快重新加载。")
	}

	if m.Config.QueryLog.SaveToFile && !newCfg.QueryLog.SaveToFile {
		logFile := m.Config.QueryLog.File
		if logFile == "" {
			logFile = "query.log"
		}
		log.Printf("持久化存储已关闭，正在删除日志文件: %s", logFile)
		if err := os.Remove(logFile); err != nil && !os.IsNotExist(err) {
			log.Printf("删除日志文件失败: %v", err)
		}
	}

	if err := m.stopInternal(); err != nil {
		log.Printf("Warning: Error stopping services during reload: %v", err)
	}

	m.Config = newCfg

	if err := m.startInternal(); err != nil {
		return fmt.Errorf("failed to restart services: %w", err)
	}

	log.Println("服务配置重载完成")
	return nil
}

func (m *ServiceManager) CheckAndDownloadGeoFiles() {
	shouldDownload := func(path string) bool {
		fi, err := os.Stat(path)
		if err != nil {
			return os.IsNotExist(err)
		}
		return fi.Size() == 0
	}

	cfg := m.Config

	if shouldDownload(cfg.GeoData.GeoIPDat) {
		if cfg.GeoData.GeoIPDownloadURL != "" {
			log.Printf("GeoIP 文件 %s 不存在或为空，正在从 %s 下载...", cfg.GeoData.GeoIPDat, cfg.GeoData.GeoIPDownloadURL)
			if err := util.DownloadFile(cfg.GeoData.GeoIPDat, cfg.GeoData.GeoIPDownloadURL, router.VerifyGeoIP); err != nil {
				log.Printf("错误: 下载 GeoIP 文件失败: %v", err)
			} else {
				log.Println("GeoIP 文件下载成功")
			}
		}
	}

	if shouldDownload(cfg.GeoData.GeoSiteDat) {
		if cfg.GeoData.GeoSiteDownloadURL != "" {
			log.Printf("GeoSite 文件 %s 不存在或为空，正在从 %s 下载...", cfg.GeoData.GeoSiteDat, cfg.GeoData.GeoSiteDownloadURL)
			if err := util.DownloadFile(cfg.GeoData.GeoSiteDat, cfg.GeoData.GeoSiteDownloadURL, router.VerifyGeoSite); err != nil {
				log.Printf("错误: 下载 GeoSite 文件失败: %v", err)
			} else {
				log.Println("GeoSite 文件下载成功")
			}
		}
	}
}

func (m *ServiceManager) ForceDownloadGeoFiles() {
	cfg := m.Config
	if cfg.GeoData.GeoIPDownloadURL != "" {
		log.Printf("正在自动更新 GeoIP 数据...")
		if err := util.DownloadFile(cfg.GeoData.GeoIPDat, cfg.GeoData.GeoIPDownloadURL, router.VerifyGeoIP); err != nil {
			log.Printf("更新 GeoIP 失败: %v", err)
		}
	}
	if cfg.GeoData.GeoSiteDownloadURL != "" {
		log.Printf("正在自动更新 GeoSite 数据...")
		if err := util.DownloadFile(cfg.GeoData.GeoSiteDat, cfg.GeoData.GeoSiteDownloadURL, router.VerifyGeoSite); err != nil {
			log.Printf("更新 GeoSite 失败: %v", err)
		}
	}
}

func (m *ServiceManager) runAutoUpdate() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	lastAttempt := time.Time{}

	for {
		select {
		case <-m.stopAutoUpdate:
			return
		case <-ticker.C:
			m.mu.Lock()
			autoUpdate := m.Config.GeoData.AutoUpdate
			geoIPFile := m.Config.GeoData.GeoIPDat
			m.mu.Unlock()

			if autoUpdate == "" {
				continue
			}

			now := time.Now()
			loc, err := time.LoadLocation("Asia/Shanghai")
			if err == nil {
				now = now.In(loc)
			} else {
			}

			parsed, err := time.Parse("15:04", autoUpdate)
			if err != nil {
				continue
			}

			targetTime := time.Date(now.Year(), now.Month(), now.Day(), parsed.Hour(), parsed.Minute(), 0, 0, now.Location())

			shouldUpdate := false

			if now.After(targetTime) || now.Equal(targetTime) {
				fi, err := os.Stat(geoIPFile)
				if err != nil {
					shouldUpdate = true
				} else {
					modTime := fi.ModTime().In(now.Location())
					if modTime.Before(targetTime) {
						shouldUpdate = true
					}
				}
			}

			if shouldUpdate {
				if time.Since(lastAttempt) < 1*time.Hour {
					continue
				}

				log.Println("触发计划的 Geo 数据更新 (检测到数据过时)...")
				lastAttempt = time.Now()

				m.ForceDownloadGeoFiles()

				m.mu.Lock()
				m.GeoManager = nil
				debug.FreeOSMemory()
				m.mu.Unlock()

				if err := m.Reload(m.Config); err != nil {
					log.Printf("Geo 更新后重载失败: %v", err)
				}
			}
		}
	}
}

func (m *ServiceManager) startInternal() error {
	cfg := m.Config

	if m.GeoManager == nil {
		geoManager, err := router.NewGeoDataManager(cfg.GeoData.GeoIPDat, cfg.GeoData.GeoSiteDat)
		if err != nil {
			return fmt.Errorf("GeoManager init failed: %w", err)
		}
		m.GeoManager = geoManager
	}

	logFile := cfg.QueryLog.File
	if cfg.QueryLog.SaveToFile && logFile == "" {
		logFile = "query.log"
	}
	m.QueryLog = querylog.NewQueryLogger(cfg.QueryLog.Enabled, cfg.QueryLog.MaxHistory, cfg.QueryLog.MaxSizeMB, logFile, cfg.QueryLog.SaveToFile)

	m.Router = router.NewRouter(cfg, m.GeoManager, m.QueryLog)

	cm, err := util.NewCertManager(cfg)
	if err != nil {
		log.Printf("无法初始化自动证书管理器: %v (将回退到本地证书)", err)
		m.CertManager = nil
	} else {
		m.CertManager = cm
	}

	if cfg.AutoCert.Enabled && m.CertManager != nil {
		m.ACMEServer = &http.Server{
			Addr: ":80",
			Handler: m.CertManager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})),
		}
		go func() {
			log.Println("Starting HTTP server on :80 for ACME challenges")
			if err := m.ACMEServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("ACME HTTP server failed: %v", err)
			}
		}()
	}

	if cfg.Listen.DNSUDP != "" || cfg.Listen.DNSTCP != "" {
		m.DNSServer = server.NewDNSServer(cfg, m.Router)
		m.DNSServer.Start()
	}

	if cfg.Listen.DOT != "" {
		m.DoTServer = server.NewDoTServer(cfg, m.Router, m.CertManager)
		if m.DoTServer != nil {
			m.DoTServer.Start()
		}
	}

	if cfg.Listen.DOQ != "" {
		m.DoQServer = server.NewDoQServer(cfg, m.Router, m.CertManager)
		if m.DoQServer != nil {
			m.DoQServer.Start()
		}
	}

	if cfg.Listen.DOH != "" {
		m.DoHServer = server.NewDoHServer(cfg, m.Router, m.CertManager)
		if m.DoHServer != nil {
			m.DoHServer.Start()
		}
	}

	return nil
}

func (m *ServiceManager) stopInternal() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if m.ACMEServer != nil {
		m.ACMEServer.Shutdown(ctx)
		m.ACMEServer = nil
	}

	if m.DNSServer != nil {
		m.DNSServer.Stop()
		m.DNSServer = nil
	}

	if m.DoTServer != nil {
		m.DoTServer.Stop()
		m.DoTServer = nil
	}

	if m.DoQServer != nil {
		m.DoQServer.Stop()
		m.DoQServer = nil
	}

	if m.DoHServer != nil {
		m.DoHServer.Stop()
		m.DoHServer = nil
	}

	return nil
}

func (m *ServiceManager) GetCertManager() *util.CertManager {
	return m.CertManager
}
