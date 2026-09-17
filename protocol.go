package cloudflare

// Wire types for POST /v1/step.

type stepStart struct {
	URL               string `json:"url"`
	UserAgent         string `json:"userAgent"`
	FinishAtForm      bool   `json:"finishAtForm"`
	ClientPacingV1    bool   `json:"clientPacingV1"`
	ClientJarWritesV1 bool   `json:"clientJarWritesV1"`
}

type stepAdvance struct {
	Context  string        `json:"context,omitempty"`
	Sequence int64         `json:"sequence,omitempty"`
	Start    *stepStart    `json:"start,omitempty"`
	Response *stepResponse `json:"response,omitempty"`
	Abort    bool          `json:"abort,omitempty"`
}

type stepHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type stepTiming struct {
	RequestStartMs  int64 `json:"requestStartMs"`
	ResponseStartMs int64 `json:"responseStartMs"`
	DurationMs      int64 `json:"durationMs"`
	PacingUs        int64 `json:"pacingUs"`
	WireBytes       *int  `json:"wireBytes,omitempty"`
}

type stepResponse struct {
	Status  int          `json:"status,omitempty"`
	Headers []stepHeader `json:"headers,omitempty"`
	Data    string       `json:"data,omitempty"`
	DataBin []byte       `json:"dataBin,omitempty"`
	Error   string       `json:"error,omitempty"`
	Timing  *stepTiming  `json:"timing,omitempty"`
}

type stepCookie struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Path        string `json:"path,omitempty"`
	ExpiresUnix int64  `json:"expiresUnix,omitempty"`
	Secure      bool   `json:"secure,omitempty"`
	SameSite    string `json:"sameSite,omitempty"`
}

type stepFailure struct {
	Kind         string `json:"kind"`
	Owner        string `json:"owner"`
	RetrySafe    bool   `json:"retrySafe"`
	RetryAfterMs int64  `json:"retryAfterMs,omitempty"`
}

type stepNext struct {
	Kind         string `json:"kind"`
	RetryAfterMs int64  `json:"retryAfterMs,omitempty"`
}

type stepResult struct {
	Outcome   string `json:"outcome"`
	Clearance string `json:"clearance,omitempty"`
}

type stepOutput struct {
	Kind        string       `json:"kind"`
	Context     string       `json:"context"`
	Sequence    int64        `json:"sequence"`
	Step        string       `json:"step"`
	Method      string       `json:"method"`
	PayloadURL  string       `json:"payloadUrl"`
	Payload     string       `json:"payload"`
	Headers     []stepHeader `json:"headers"`
	HeaderOrder []string     `json:"headerOrder"`
	Host        string       `json:"host"`
	TimeoutMs   int64        `json:"timeoutMs"`
	PacingMs    int64        `json:"pacingMs"`
	SetCookies  []stepCookie `json:"setCookies"`
	Result      *stepResult  `json:"result"`
	Failure     *stepFailure `json:"failure"`
	Next        *stepNext    `json:"next"`
}

type apiErrorBody struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RetrySafe bool   `json:"retrySafe"`
	RequestID string `json:"requestId"`
}
