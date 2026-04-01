package router

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"doh-autoproxy/internal/client"
	"doh-autoproxy/internal/config"
	"doh-autoproxy/internal/querylog"
	"doh-autoproxy/internal/resolver"

	"github.com/miekg/dns"
)

type RegexRule struct {
	Pattern *regexp.Regexp
	Target  string
}

type Router struct {
	config          *config.Config
	geo             *GeoDataManager
	logger          *querylog.QueryLogger
	cnClients       []client.DNSClient
	overseasClients []client.DNSClient

	cnStats       []*client.StatsClient
	overseasStats []*client.StatsClient

	regexRules []RegexRule
}

func NewRouter(cfg *config.Config, geoManager *GeoDataManager, logger *querylog.QueryLogger) *Router {
	r := &Router{
		config: cfg,
		geo:    geoManager,
		logger: logger,
	}

	for domain, target := range cfg.Rules {
		if strings.HasPrefix(domain, "regexp:") {
			pattern := strings.TrimPrefix(domain, "regexp:")
			re, err := regexp.Compile(pattern)
			if err != nil {
				log.Printf("忽略无效的正则规则: %s -> %v", domain, err)
				continue
			}
			r.regexRules = append(r.regexRules, RegexRule{
				Pattern: re,
				Target:  target,
			})
		}
	}

	bootstrapper := resolver.NewBootstrapper(cfg.BootstrapDNS)

	for _, upstreamCfg := range cfg.Upstreams.CN {
		c, err := client.NewDNSClient(upstreamCfg, bootstrapper)
		if err != nil {
			log.Printf("Failed to initialize CN upstream %s: %v", upstreamCfg.Address, err)
			continue
		}
		sc := client.NewStatsClient(c, upstreamCfg.Address, upstreamCfg.Protocol, "CN")
		r.cnClients = append(r.cnClients, sc)
		r.cnStats = append(r.cnStats, sc)
	}

	for _, upstreamCfg := range cfg.Upstreams.Overseas {
		c, err := client.NewDNSClient(upstreamCfg, bootstrapper)
		if err != nil {
			log.Printf("Failed to initialize Overseas upstream %s: %v", upstreamCfg.Address, err)
			continue
		}
		sc := client.NewStatsClient(c, upstreamCfg.Address, upstreamCfg.Protocol, "Overseas")
		r.overseasClients = append(r.overseasClients, sc)
		r.overseasStats = append(r.overseasStats, sc)
	}

	return r
}

func (r *Router) GetUpstreamStats() []interface{} {
	var stats []interface{}
	for _, s := range r.cnStats {
		stats = append(stats, s.GetStats())
	}
	for _, s := range r.overseasStats {
		stats = append(stats, s.GetStats())
	}
	return stats
}

func (r *Router) Route(ctx context.Context, req *dns.Msg, clientIP string) (*dns.Msg, error) {
	start := time.Now()
	if len(req.Question) == 0 {
		return nil, fmt.Errorf("no question")
	}

	downstreamECS := client.ExtractECS(req)
	resp, upstream, err := r.routeInternal(ctx, req)
	if err == nil && resp != nil {
		resp, upstream = r.normalizeServiceBindingNegativeResponse(ctx, req, resp, upstream)
	}

	duration := time.Since(start).Milliseconds()

	qName := req.Question[0].Name
	qType := dns.Type(req.Question[0].Qtype).String()

	status := "ERROR"
	answer := ""
	var answerRecords []querylog.AnswerRecord

	if err == nil && resp != nil {
		status = dns.RcodeToString[resp.Rcode]
		if len(resp.Answer) > 0 {
			parts := strings.Fields(resp.Answer[0].String())
			if len(parts) > 4 {
				answer = strings.Join(parts[4:], " ")
			} else {
				answer = resp.Answer[0].String()
			}
			if len(resp.Answer) > 1 {
				answer += fmt.Sprintf(" (+%d more)", len(resp.Answer)-1)
			}

			for _, ans := range resp.Answer {
				parts := strings.Fields(ans.String())
				data := ""
				if len(parts) > 4 {
					data = strings.Join(parts[4:], " ")
				} else {
					data = ans.String()
				}
				answerRecords = append(answerRecords, querylog.AnswerRecord{
					Name: ans.Header().Name,
					Type: dns.Type(ans.Header().Rrtype).String(),
					TTL:  ans.Header().Ttl,
					Data: data,
				})
			}
		}
	}

	if r.logger != nil {
		r.logger.AddLog(&querylog.LogEntry{
			ClientIP:      clientIP,
			DownstreamECS: downstreamECS,
			Domain:        qName,
			Type:          qType,
			Upstream:      upstream,
			Answer:        answer,
			AnswerRecords: answerRecords,
			DurationMs:    duration,
			Status:        status,
		})
	}

	if resp != nil && resp.Rcode == dns.RcodeNameError {
		for _, ans := range resp.Answer {
			ans.Header().Ttl = 0
		}
		for _, ns := range resp.Ns {
			ns.Header().Ttl = 0
		}
		for _, extra := range resp.Extra {
			extra.Header().Ttl = 0
		}
	}

	return resp, err
}

func isServiceBindingQuestion(req *dns.Msg) bool {
	if len(req.Question) == 0 {
		return false
	}

	qType := req.Question[0].Qtype
	return qType == dns.TypeHTTPS || qType == dns.TypeSVCB
}

func newExistenceCheckRequest(req *dns.Msg, qName string) *dns.Msg {
	checkReq := new(dns.Msg)
	checkReq.SetQuestion(dns.Fqdn(qName), dns.TypeA)
	checkReq.Id = req.Id
	checkReq.RecursionDesired = req.RecursionDesired
	checkReq.CheckingDisabled = req.CheckingDisabled

	if opt := req.IsEdns0(); opt != nil {
		checkReq.SetEdns0(opt.UDPSize(), opt.Do())
	}

	return checkReq
}

func synthesizeNoDataResponse(req *dns.Msg, resp *dns.Msg) *dns.Msg {
	normalized := resp.Copy()
	normalized.Rcode = dns.RcodeSuccess
	normalized.Answer = nil
	normalized.Ns = nil
	normalized.Extra = nil
	for _, extra := range resp.Extra {
		if extra.Header().Rrtype == dns.TypeOPT {
			normalized.Extra = append(normalized.Extra, dns.Copy(extra))
		}
	}
	normalized.Question = append([]dns.Question(nil), req.Question...)
	return normalized
}

func (r *Router) normalizeServiceBindingNegativeResponse(ctx context.Context, req, resp *dns.Msg, upstream string) (*dns.Msg, string) {
	if resp == nil || resp.Rcode != dns.RcodeNameError || !isServiceBindingQuestion(req) {
		return resp, upstream
	}

	candidates := matchNames(req.Question[0].Name)
	if len(candidates) <= 1 {
		return resp, upstream
	}

	originName := candidates[len(candidates)-1]
	checkReq := newExistenceCheckRequest(req, originName)
	checkResp, _, err := r.routeInternal(ctx, checkReq)
	if err != nil || checkResp == nil || checkResp.Rcode != dns.RcodeSuccess {
		return resp, upstream
	}

	return synthesizeNoDataResponse(req, resp), upstream + "/Compat-NODATA"
}

// matchNames returns the original qname plus progressively stripped variants
// without leading underscore labels. This lets service-style names such as
// _8443._https.example.com inherit routing policy from example.com while still
// sending the original qname to upstream resolvers.
func matchNames(qName string) []string {
	qName = strings.ToLower(strings.TrimSuffix(qName, "."))
	if qName == "" {
		return nil
	}

	names := []string{qName}
	seen := map[string]struct{}{qName: {}}
	labels := dns.SplitDomainName(qName)

	for i := 0; i < len(labels)-1; i++ {
		if !strings.HasPrefix(labels[i], "_") {
			break
		}

		candidate := strings.Join(labels[i+1:], ".")
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}

		names = append(names, candidate)
		seen[candidate] = struct{}{}
	}

	return names
}

func (r *Router) lookupRule(names []string) (string, bool) {
	for _, name := range names {
		if rule, ok := r.config.Rules[name]; ok {
			return rule, true
		}
	}
	return "", false
}

func (r *Router) lookupRegexRule(names []string) (string, bool) {
	for _, name := range names {
		for _, rr := range r.regexRules {
			if rr.Pattern.MatchString(name) {
				return rr.Target, true
			}
		}
	}
	return "", false
}

func (r *Router) lookupGeoSite(names []string) string {
	for _, name := range names {
		if geoSiteRule := r.geo.LookupGeoSite(name); geoSiteRule != "" {
			return geoSiteRule
		}
	}
	return ""
}

func hostOverrideResponse(req *dns.Msg, ip net.IP) (*dns.Msg, bool) {
	if ip == nil || len(req.Question) == 0 {
		return nil, false
	}

	qType := req.Question[0].Qtype
	isIPv4 := ip.To4() != nil
	if qType != dns.TypeANY &&
		((qType == dns.TypeA && !isIPv4) ||
			(qType == dns.TypeAAAA && isIPv4) ||
			(qType != dns.TypeA && qType != dns.TypeAAAA)) {
		return nil, false
	}

	m := new(dns.Msg)
	m.SetReply(req)
	rrHeader := dns.RR_Header{
		Name:  req.Question[0].Name,
		Class: dns.ClassINET,
		Ttl:   60,
	}
	if isIPv4 {
		rrHeader.Rrtype = dns.TypeA
		m.Answer = append(m.Answer, &dns.A{Hdr: rrHeader, A: ip.To4()})
	} else {
		rrHeader.Rrtype = dns.TypeAAAA
		m.Answer = append(m.Answer, &dns.AAAA{Hdr: rrHeader, AAAA: ip})
	}

	return m, true
}

func (r *Router) routeInternal(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	qName := strings.ToLower(strings.TrimSuffix(req.Question[0].Name, "."))
	matchCandidates := matchNames(qName)

	if ipStr, ok := r.config.Hosts[qName]; ok {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, "Hosts", fmt.Errorf("自定义Hosts中存在无效IP地址: %s for %s", ipStr, qName)
		}

		if resp, ok := hostOverrideResponse(req, ip); ok {
			return resp, "Hosts", nil
		}
	}

	if rule, ok := r.lookupRule(matchCandidates); ok {
		switch strings.ToLower(rule) {
		case "cn":
			resp, err := client.RaceResolve(ctx, req, r.cnClients)
			return resp, "Rule(CN)", err
		case "overseas":
			resp, err := client.RaceResolve(ctx, req, r.overseasClients)
			return resp, "Rule(Overseas)", err
		default:
		}
	}

	if regexRule, ok := r.lookupRegexRule(matchCandidates); ok {
		switch strings.ToLower(regexRule) {
		case "cn":
			resp, err := client.RaceResolve(ctx, req, r.cnClients)
			return resp, "Rule(Regex/CN)", err
		case "overseas":
			resp, err := client.RaceResolve(ctx, req, r.overseasClients)
			return resp, "Rule(Regex/Overseas)", err
		}
	}

	if geoSiteRule := r.lookupGeoSite(matchCandidates); geoSiteRule != "" {
		switch strings.ToLower(geoSiteRule) {
		case "cn":
			resp, err := client.RaceResolve(ctx, req, r.cnClients)
			return resp, "GeoSite(CN)", err
		default:
			resp, err := client.RaceResolve(ctx, req, r.overseasClients)
			return resp, "GeoSite(Overseas)", err
		}
	}

	// GeoSite 未命中：同时查询国内和海外 DNS，根据结果判断
	type dualResult struct {
		resp   *dns.Msg
		err    error
		source string
	}

	dualCh := make(chan dualResult, 2)

	go func() {
		resp, err := client.RaceResolve(ctx, req.Copy(), r.overseasClients)
		dualCh <- dualResult{resp: resp, err: err, source: "overseas"}
	}()
	go func() {
		resp, err := client.RaceResolve(ctx, req.Copy(), r.cnClients)
		dualCh <- dualResult{resp: resp, err: err, source: "cn"}
	}()

	var overseasResult, cnResult *dualResult
	for i := 0; i < 2; i++ {
		r := <-dualCh
		rCopy := r
		if r.source == "overseas" {
			overseasResult = &rCopy
		} else {
			cnResult = &rCopy
		}
	}

	// 海外成功且有应答
	if overseasResult.err == nil && overseasResult.resp != nil && overseasResult.resp.Rcode == dns.RcodeSuccess {
		var resolvedIP net.IP
		for _, ans := range overseasResult.resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				resolvedIP = a.A
				break
			}
			if aaaa, ok := ans.(*dns.AAAA); ok {
				resolvedIP = aaaa.AAAA
				break
			}
		}

		// 如果解析出的 IP 是国内的，用国内 DNS 的结果（更准确）
		if resolvedIP != nil && r.geo.IsCNIP(resolvedIP) {
			if cnResult.err == nil && cnResult.resp != nil && cnResult.resp.Rcode == dns.RcodeSuccess {
				return cnResult.resp, "GeoIP(CN)", nil
			}
			// 国内 DNS 失败，仍然返回海外结果
			return overseasResult.resp, "GeoIP(CN/Fallback-Overseas)", nil
		}

		return overseasResult.resp, "GeoIP(Overseas)", nil
	}

	// 海外失败或 NXDOMAIN/SERVFAIL，尝试用国内结果
	if cnResult.err == nil && cnResult.resp != nil && cnResult.resp.Rcode == dns.RcodeSuccess {
		log.Printf("海外DNS解析失败或无结果，使用国内DNS结果: %s", qName)
		return cnResult.resp, "GeoIP(Fallback/CN)", nil
	}

	// 两边都失败，返回最有意义的错误
	if overseasResult.err == nil && overseasResult.resp != nil {
		return overseasResult.resp, "GeoIP(Overseas)", nil
	}
	if cnResult.err == nil && cnResult.resp != nil {
		return cnResult.resp, "GeoIP(CN)", nil
	}

	// 全部出错
	if overseasResult.err != nil {
		return nil, "GeoIP(Error)", fmt.Errorf("所有DNS查询均失败: overseas=%v, cn=%v", overseasResult.err, cnResult.err)
	}
	return nil, "GeoIP(Error)", cnResult.err
}
