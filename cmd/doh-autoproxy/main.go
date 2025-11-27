package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/router"
	"doh-autoproxy/internal/server"
	"doh-autoproxy/internal/util"
)

func main() {
	fmt.Println("DoH Automatic Traffic Splitting Service is starting...")

	configPath := config.GetDefaultConfigPath()
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("无法加载配置: %v", err)
	}

	log.Println("配置加载成功")

	shouldDownload := func(path string) bool {
		fi, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return true
			}
			return false
		}
		return fi.Size() == 0
	}

	if shouldDownload(cfg.GeoData.GeoIPDat) {
		if cfg.GeoData.GeoIPDownloadURL != "" {
			log.Printf("GeoIP 文件 %s 不存在或为空，正在从 %s 下载...", cfg.GeoData.GeoIPDat, cfg.GeoData.GeoIPDownloadURL)
			if err := util.DownloadFile(cfg.GeoData.GeoIPDat, cfg.GeoData.GeoIPDownloadURL); err != nil {
				log.Fatalf("下载 GeoIP 文件失败: %v", err)
			}
			log.Println("GeoIP 文件下载成功")
		} else {
			if _, err := os.Stat(cfg.GeoData.GeoIPDat); os.IsNotExist(err) {
				log.Fatalf("GeoIP 文件 %s 不存在且未配置下载地址", cfg.GeoData.GeoIPDat)
			}
		}
	}

	if shouldDownload(cfg.GeoData.GeoSiteDat) {
		if cfg.GeoData.GeoSiteDownloadURL != "" {
			log.Printf("GeoSite 文件 %s 不存在或为空，正在从 %s 下载...", cfg.GeoData.GeoSiteDat, cfg.GeoData.GeoSiteDownloadURL)
			if err := util.DownloadFile(cfg.GeoData.GeoSiteDat, cfg.GeoData.GeoSiteDownloadURL); err != nil {
				log.Fatalf("下载 GeoSite 文件失败: %v", err)
			}
			log.Println("GeoSite 文件下载成功")
		} else {
			if _, err := os.Stat(cfg.GeoData.GeoSiteDat); os.IsNotExist(err) {
				log.Fatalf("GeoSite 文件 %s 不存在且未配置下载地址", cfg.GeoData.GeoSiteDat)
			}
		}
	}

	geoManager, err := router.NewGeoDataManager(cfg.GeoData.GeoIPDat, cfg.GeoData.GeoSiteDat)
	if err != nil {
		log.Fatalf("无法初始化Geo数据管理器: %v", err)
	}
	log.Println("Geo数据管理器初始化成功")

	mainRouter := router.NewRouter(cfg, geoManager)
	log.Println("路由器初始化成功")

	certManager, err := util.NewCertManager(cfg)
	if err != nil {
		log.Printf("无法初始化自动证书管理器: %v (将回退到本地证书)", err)
		certManager = nil
	} else if cfg.AutoCert.Enabled {
		go func() {
			log.Println("Starting HTTP server on :80 for ACME challenges and redirect")
			if err := http.ListenAndServe(":80", certManager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}))); err != nil {
				log.Printf("HTTP server on :80 failed: %v (ACME HTTP-01 challenge may fail)", err)
			}
		}()
	}

	if cfg.Listen.DNSUDP != "" || cfg.Listen.DNSTCP != "" {
		dnsServer := server.NewDNSServer(cfg, mainRouter)
		dnsServer.Start()
	} else {
		log.Println("标准DNS服务未配置 (UDP/TCP 均为空)")
	}

	if cfg.Listen.DOT != "" {
		dotServer := server.NewDoTServer(cfg, mainRouter, certManager)
		if dotServer != nil {
			dotServer.Start()
		} else {
			log.Println("DoT服务器初始化失败")
		}
	} else {
		log.Println("DoT服务未配置")
	}

	if cfg.Listen.DOQ != "" {
		doqServer := server.NewDoQServer(cfg, mainRouter, certManager)
		if doqServer != nil {
			doqServer.Start()
		} else {
			log.Println("DoQ服务器初始化失败")
		}
	} else {
		log.Println("DoQ服务未配置")
	}

	if cfg.Listen.DOH != "" {
		dohServer := server.NewDoHServer(cfg, mainRouter, certManager)
		if dohServer != nil {
			dohServer.Start()
		} else {
			log.Println("DoH服务器初始化失败")
		}
	} else {
		log.Println("DoH服务未配置")
	}

	log.Println("所有服务已启动")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("收到关闭信号，正在停止服务...")

	log.Println("服务已停止")
}
