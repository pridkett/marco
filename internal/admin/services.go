package admin

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
	"github.com/pridkett/marco/internal/filter"
)

type serviceCard struct {
	ID, Name, Category, Version string
	URL                         string
	HasIcon, Custom             bool
	Count                       int
}

type servicePage struct {
	Search, Category string
	Categories       []string
	Cards            []serviceCard
	Detail           *serviceCard
	Rules            []filter.ServiceRule
	RuleSearch       string
	Host, Type       string
	Types            []string
	Result, Error    string
	Total            int
	Back             string
}

func (p *servicePage) catalogURL(id string) string {
	params := url.Values{}
	if p.Search != "" {
		params.Set("search", p.Search)
	}
	if p.Category != "" {
		params.Set("category", p.Category)
	}
	if id != "" {
		params.Set("id", id)
	}
	if len(params) == 0 {
		return "/services"
	}
	return "/services?" + params.Encode()
}

func categoryName(id string) string {
	switch id {
	case "ai":
		return "AI"
	case "cdn":
		return "CDN"
	case "social_network":
		return "Social networks"
	case "":
		return "Custom"
	default:
		return strings.ToUpper(id[:1]) + strings.ReplaceAll(id[1:], "_", " ")
	}
}

func (s *server) servicePage(p *page, r *http.Request, desired config.Desired) int {
	query := r.URL.Query()
	cardData := s.serviceCards(desired)
	result := &p.Services
	result.Total = len(cardData)
	result.Search = strings.TrimSpace(query.Get("search"))
	result.Category = query.Get("category")
	if id := query.Get("id"); id != "" {
		card, ok := cardData[id]
		if !ok {
			p.Feedback.Error = "Service not found."
			return http.StatusNotFound
		}
		p.Title = card.Name
		result.Detail = &card
		result.Back = result.catalogURL("")
		spec, custom := desired.Services[id]
		if !custom {
			spec.Rules = s.hooks.Catalog.Entries[id].Rules
		}
		result.Rules = filter.DescribeService(spec)
		result.RuleSearch = strings.TrimSpace(query.Get("rule"))
		if search := strings.ToLower(result.RuleSearch); search != "" {
			result.Rules = slices.DeleteFunc(result.Rules, func(rule filter.ServiceRule) bool {
				return !strings.Contains(strings.ToLower(rule.Text+" "+rule.Condition), search)
			})
		}
		s.testService(result, query.Get("host"), query.Get("type"), id)
		return http.StatusOK
	}
	categories := make(map[string]bool)
	search := strings.ToLower(result.Search)
	for _, card := range cardData {
		categories[card.Category] = true
		if result.Category != "" && result.Category != card.Category {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(card.Name+" "+card.ID+" "+card.Category), search) {
			continue
		}
		result.Cards = append(result.Cards, card)
	}
	result.Categories = slices.Sorted(maps.Keys(categories))
	slices.SortFunc(result.Cards, compareServices)
	for i := range result.Cards {
		result.Cards[i].URL = result.catalogURL(result.Cards[i].ID)
	}
	return http.StatusOK
}

func compareServices(left, right serviceCard) int {
	if order := strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name)); order != 0 {
		return order
	}
	return strings.Compare(left.ID, right.ID)
}

func (s *server) serviceCards(desired config.Desired) map[string]serviceCard {
	cards := make(map[string]serviceCard)
	if catalog := s.hooks.Catalog; catalog != nil {
		for id, entry := range catalog.Entries {
			cards[id] = serviceCard{ID: id, Name: entry.Name, Category: categoryName(entry.Category),
				Version: catalog.Version, Count: len(entry.Rules), HasIcon: true}
		}
	}
	for id, spec := range desired.Services {
		card, exists := cards[id]
		if !exists {
			card = serviceCard{ID: id, Name: id, Category: categoryName("")}
		}
		card.Version, card.Count, card.Custom = spec.Version, len(spec.Domains)+len(spec.Rules), true
		cards[id] = card
	}
	return cards
}

func (s *server) testService(result *servicePage, host, typ, id string) {
	result.Types = []string{"A", "AAAA", "CNAME", "HTTPS", "SVCB", "SRV", "TXT", "ANY"}
	result.Host = host
	result.Type = strings.ToUpper(typ)
	if result.Type == "" {
		result.Type = "A"
	}
	if result.Host == "" {
		return
	}
	name, err := config.Name(host)
	qtype, supported := dns.StringToType[result.Type]
	switch {
	case err != nil:
		result.Error = "Enter a valid DNS hostname."
	case !supported || qtype == 0:
		result.Error = "Choose a DNS record type."
	case s.hooks.MatchService == nil:
		result.Error = "The service matcher is unavailable."
	default:
		match := s.hooks.MatchService(id, name, qtype)
		if match.Found {
			result.Result = fmt.Sprintf("%s %s matches %s", name, result.Type, match.Name)
		} else {
			result.Result = fmt.Sprintf("No match for %s %s in this service.", name, result.Type)
		}
	}
}

func (s *server) serviceIcon(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	catalog := s.hooks.Catalog
	if catalog == nil {
		http.NotFound(w, r)
		return
	}
	entry, ok := catalog.Entries[r.PathValue("id")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	fmt.Fprint(w, entry.Icon)
}
