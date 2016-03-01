// +build go1.5

package authentication

import "net/url"

func getRawPath(url *url.URL) string {
	return url.RawPath
}
