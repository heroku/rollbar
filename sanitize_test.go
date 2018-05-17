package rollbar

import "testing"

func Test_sanitize(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty",
			input: "",
			want:  "",
		},
		{
			name:  "benign",
			input: "this is a test",
			want:  "this is a test",
		},
		{
			name:  "URL with basic auth",
			input: "Post https://admin-987239487234:62A39B834@silly.atlantic-ocean-3432.rollbar.com/session: EOF",
			want:  "Post https://admin-987239487234:<REDACTED>@silly.atlantic-ocean-3432.rollbar.com/session: EOF",
		},
		{
			name:  "multiple URLs with basic auth",
			input: "Post https://admin-987239487234:62A39B834@silly.atlantic-ocean-3432.rollbar.com/session: EOF and then Get https://admin-14245262:6asdfsadf@proxy.atlantic-ocean-3432.rollbar.com/session: EOF",
			want:  "Post https://admin-987239487234:<REDACTED>@silly.atlantic-ocean-3432.rollbar.com/session: EOF and then Get https://admin-14245262:<REDACTED>@proxy.atlantic-ocean-3432.rollbar.com/session: EOF",
		},
		{
			name:  "URL without basic auth",
			input: "Post https://admin-987239487234@silly.atlantic-ocean-3432.rollbar.com/session: EOF",
			want:  "Post https://admin-987239487234@silly.atlantic-ocean-3432.rollbar.com/session: EOF",
		},
		{
			name:  "URL without user info",
			input: "Post https://silly.atlantic-ocean-3432.rollbar.com/session: EOF",
			want:  "Post https://silly.atlantic-ocean-3432.rollbar.com/session: EOF",
		},
		{
			name:  "URL with tcp scheme",
			input: "Post tcp://admin-987239487234:62A39B834@silly.atlantic-ocean-3432.rollbar.com/session: EOF",
			want:  "Post tcp://admin-987239487234:<REDACTED>@silly.atlantic-ocean-3432.rollbar.com/session: EOF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitize(tt.input); got != tt.want {
				t.Errorf("sanitize() = %v, want %v", got, tt.want)
			}
		})
	}
}
