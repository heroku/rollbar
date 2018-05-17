package rollbar

import "regexp"

var REGEX_URL_WITH_BASIC_AUTH = regexp.MustCompile("(\\w+://.+?:).+?(@)")

func sanitize(message string) string {
	message = REGEX_URL_WITH_BASIC_AUTH.ReplaceAllString(message, "$1<REDACTED>$2")
	return message
}
