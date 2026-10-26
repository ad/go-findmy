package gsa

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
)

type CookieKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Session struct {
	AnisetteHeaders map[string]string     `json:"anisetteHeaders"`
	Cookies         map[string][]CookieKV `json:"cookies"`
	DSID            string                `json:"dsid"`
	Tokens          map[string]string     `json:"tokens"`
}

func (c *Client) requestURLs() []string {
	return []string{
		gsaBaseURL + "/grandslam/GsService2",
		gsaBaseURL + "/auth/verify/trusteddevice",
		gsaBaseURL + "/grandslam/GsService2/validate",
		idmsaBaseURL + "/auth/verify/phone",
		idmsaBaseURL + "/auth/verify/phone/securitycode",
	}
}

func (c *Client) Snapshot(dsid string, tokens map[string]string) (Session, error) {
	if c.cachedAnisetteHeaders == nil {
		return Session{}, fmt.Errorf("gsa: cannot snapshot session before anisette headers are fetched")
	}
	cookies := map[string][]CookieKV{}
	seen := map[string]bool{}
	for _, ustr := range c.requestURLs() {
		u, err := url.Parse(ustr)
		if err != nil {
			continue
		}
		var kvs []CookieKV
		for _, ck := range c.cookieJar.Cookies(u) {
			key := u.Host + "\x00" + ck.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			kvs = append(kvs, CookieKV{Name: ck.Name, Value: ck.Value})
		}
		if len(kvs) > 0 {
			cookies[ustr] = kvs
		}
	}
	return Session{
		AnisetteHeaders: maps.Clone(c.cachedAnisetteHeaders),
		Cookies:         cookies,
		DSID:            dsid,
		Tokens:          maps.Clone(tokens),
	}, nil
}

func NewClientFromSession(anisette AnisetteProvider, sess Session) *Client {
	c := NewClient(anisette)
	if sess.AnisetteHeaders != nil {
		c.cachedAnisetteHeaders = maps.Clone(sess.AnisetteHeaders)
	}
	for ustr, kvs := range sess.Cookies {
		u, err := url.Parse(ustr)
		if err != nil {
			continue
		}
		cks := make([]*http.Cookie, 0, len(kvs))
		for _, kv := range kvs {
			cks = append(cks, &http.Cookie{Name: kv.Name, Value: kv.Value})
		}
		c.cookieJar.SetCookies(u, cks)
	}
	return c
}
