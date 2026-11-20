package config

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const catalogFilename = "services.json"

var catalogID = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

type CatalogEntry struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"group"`
	Icon     string   `json:"icon_svg"`
	Rules    []string `json:"rules"`
}

type ServiceCatalog struct {
	Version string
	Entries map[string]CatalogEntry
}

func (c *ServiceCatalog) Definitions() map[string]Service {
	if c == nil {
		return nil
	}
	services := make(map[string]Service, len(c.Entries))
	for id, entry := range c.Entries {
		services[id] = Service{Version: c.Version, Rules: entry.Rules}
	}
	return services
}

func readCatalog(path, configDirectory string) (*ServiceCatalog, error) {
	if path != "" {
		return LoadServiceCatalog(path)
	}
	candidates := []string{filepath.Join(configDirectory, "catalog", catalogFilename)}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "catalog", catalogFilename))
	}
	candidates = append(candidates, filepath.Join("catalog", catalogFilename))
	for _, name := range candidates {
		catalog, err := LoadServiceCatalog(name)
		if !errors.Is(err, os.ErrNotExist) {
			return catalog, err
		}
	}
	return nil, nil
}

func LoadServiceCatalog(path string) (*ServiceCatalog, error) {
	data, err := readBounded(path, 2<<20)
	if err != nil {
		return nil, err
	}
	var source struct {
		Entries []CatalogEntry `json:"blocked_services"`
		Groups  []struct {
			ID string `json:"id"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(data, &source); err != nil {
		return nil, fmt.Errorf("decode service catalog: %w", err)
	}
	if len(source.Entries) == 0 || len(source.Entries) > 1024 || len(source.Groups) > 128 {
		return nil, errors.New("service catalog requires 1–1024 services and at most 128 categories")
	}
	groups := make(map[string]bool, len(source.Groups))
	for _, group := range source.Groups {
		if !catalogID.MatchString(group.ID) || groups[group.ID] {
			return nil, fmt.Errorf("invalid or duplicate service category %q", group.ID)
		}
		groups[group.ID] = true
	}
	sum := sha256.Sum256(data)
	c := &ServiceCatalog{Version: fmt.Sprintf("sha256:%x", sum), Entries: make(map[string]CatalogEntry, len(source.Entries))}
	for _, entry := range source.Entries {
		if _, exists := c.Entries[entry.ID]; exists || !catalogID.MatchString(entry.ID) || strings.TrimSpace(entry.Name) == "" ||
			len(entry.Name) > 128 || !groups[entry.Category] || len(entry.Rules) == 0 || len(entry.Rules) > 1024 {
			return nil, fmt.Errorf("invalid or duplicate service %q", entry.ID)
		}
		if err := validateServiceIcon(entry.Icon); err != nil {
			return nil, fmt.Errorf("service %q image: %w", entry.ID, err)
		}
		c.Entries[entry.ID] = entry
	}
	return c, nil
}

func validateServiceIcon(icon string) error {
	const svg = "http://www.w3.org/2000/svg"
	if len(icon) == 0 || len(icon) > 32<<10 {
		return errors.New("expected an SVG of at most 32 KiB")
	}
	decoder := xml.NewDecoder(strings.NewReader(icon))
	depth, roots := 0, 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("invalid SVG")
		}
		switch node := token.(type) {
		case xml.StartElement:
			element := node.Name.Local
			if depth == 0 {
				roots++
				if roots != 1 || element != "svg" || node.Name.Space != svg {
					return errors.New("expected a single SVG root")
				}
			}
			switch element {
			case "svg", "path", "g", "ellipse", "clipPath", "mask", "defs":
			default:
				return fmt.Errorf("unsupported SVG element %q", element)
			}
			if node.Name.Space != svg {
				return errors.New("unexpected SVG namespace")
			}
			for _, attribute := range node.Attr {
				if attribute.Name.Space != "" {
					return errors.New("unexpected SVG attribute namespace")
				}
				switch attribute.Name.Local {
				case "xmlns", "viewBox", "d", "fill", "fill-rule", "clip-rule", "stroke", "stroke-linecap",
					"id", "stroke-linejoin", "cx", "cy", "rx", "ry", "clip-path", "stroke-width", "mask",
					"stroke-miterlimit", "width", "height", "x", "y", "maskUnits", "strokeWidth", "strokeMiterlimit":
				default:
					return fmt.Errorf("unsupported SVG attribute %q", attribute.Name.Local)
				}
				if value := strings.ToLower(attribute.Value); strings.Contains(value, "url(") &&
					(!strings.HasPrefix(value, "url(#") || strings.Count(value, "url(") != 1 || !strings.HasSuffix(value, ")")) {
					return errors.New("external SVG reference")
				}
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if strings.TrimSpace(string(node)) != "" {
				return errors.New("unexpected SVG text")
			}
		case xml.Comment:
		default:
			return errors.New("unsupported SVG markup")
		}
	}
	if roots != 1 || depth != 0 {
		return errors.New("invalid SVG root")
	}
	return nil
}
