package gsa

type AnisetteProvider interface {
	Headers() (map[string]string, error)
}
