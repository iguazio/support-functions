package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"time"

	"github.com/nuclio/nuclio-sdk-go"
	"github.com/pkg/errors"
)

func Handler(context *nuclio.Context, event nuclio.Event) (interface{}, error) {
	userData := context.UserData.(UserData)
	provazio := NewProvazio(&userData, event)

	context.Logger.DebugWith("Fetching provazio systems", "provazio", provazio)
	provazioSystems, err := provazio.GetSystems()
	if err != nil {
		context.Logger.ErrorWith("Could not fetch provazio systems", "error", err)
		return nuclio.Response{
			StatusCode:  500,
			ContentType: "application/text",
			Body:        []byte("Could not fetch provazio systems"),
		}, nil
	}
	context.Logger.InfoWith("Received provazio systems", "length", len(provazioSystems))

	// build events api call attributes (kind, severity, etc)
	getSystemEventsConfiguration := BuildGetSystemEventsConfiguration(event)

	// get all systems events
	systemsChannel := make(chan SystemChannelResponse, len(provazioSystems))

	// Fire all calls
	GetSystemsEvents(context, getSystemEventsConfiguration, &systemsChannel, provazioSystems)

	return BuildFunctionResponse(context, getSystemEventsConfiguration, provazioSystems, &systemsChannel)
}

func InitContext(context *nuclio.Context) error {
	context.UserData = UserData{
		SystemCredentials: SystemCredentials{
			Username: os.Getenv("SYSTEMS_USERNAME"),
			Password: os.Getenv("SYSTEMS_PASSWORD"),
		},
		ProvazioEnv:        os.Getenv("PROVAZIO_DEFAULT_ENV"),
		ProvazioUserRemote: os.Getenv("PROVAZIO_USE_REMOTE") == "true",
		SystemApiPort:      8001,
	}
	return nil
}

type UserData struct {
	SystemCredentials
	ProvazioEnv        string
	ProvazioUserRemote bool
	SystemApiPort      int
}

type SystemChannelResponse struct {
	System System
	Error  error
}

type Result struct {
	URL             string   `json:"url"`
	ID              string   `json:"id"`
	Description     string   `json:"description,omitempty"`
	TotalRecords    int      `json:"total_records"`
	Error           string   `json:"error,omitempty"`
	EventTimestamps []string `json:"event_timestamps,omitempty"`
}

type Response struct {
	Results       []Result    `json:"results,omitempty"`
	ResultsLength int         `json:"results_length,omitempty"`
	Configuration interface{} `json:"configuration,omitempty"`
}

type GetSystemEventsConfiguration struct {
	Filters              map[string]string `json:"filters,omitempty"`
	Pagination           bool              `json:"pagination,omitempty"`
	ShowLastEvents       bool              `json:"show_last_events,omitempty"`
	ShowLastEventsLength int               `json:"show_last_events_length,omitempty"`
}

func GetSystemsEvents(context *nuclio.Context,
	getConfiguration *GetSystemEventsConfiguration,
	systemsChannel *chan SystemChannelResponse,
	provazioSystems []ProvazioSystem) {

	for _, provazioSystem := range provazioSystems {

		// collect single system events
		go getSystemEvents(context, provazioSystem, getConfiguration, *systemsChannel)
	}

}

func BuildFunctionResponse(context *nuclio.Context,
	getConfiguration *GetSystemEventsConfiguration,
	provazioSystems []ProvazioSystem,
	systemsChannel *chan SystemChannelResponse) (nuclio.Response, error) {
	var results []Result
	start := time.Now()
	ctr := 0
	for {
		if ctr == len(provazioSystems) {
			context.Logger.DebugWith("Retrieved all responses", "took", time.Since(start))
			close(*systemsChannel)
			response := Response{
				Results:       results,
				ResultsLength: len(results),
				Configuration: getConfiguration,
			}
			responseBody, err := json.Marshal(response)
			if err != nil {
				return nuclio.Response{StatusCode: 500}, nil
			}

			// response
			return nuclio.Response{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        responseBody,
			}, nil
		}
		system := <-*systemsChannel
		errMessage := ""
		if system.Error != nil {
			errMessage = system.Error.Error()
		}
		var eventTimestamps []string
		if system.System.GetSystemEventsConfiguration.ShowLastEvents {
			length := system.System.GetSystemEventsConfiguration.ShowLastEventsLength
			length = int(math.Min(float64(length), float64(len(system.System.Events.Data))))
			for i := 0; i < length; i++ {
				eventTimestamps = append(eventTimestamps, system.System.Events.Data[i].Attributes.TimestampIso8601)
			}
		}
		results = append(results, Result{
			URL:             system.System.GetURL(),
			ID:              system.System.GetID(),
			Description:     system.System.ProvazioSystem.Spec.Description,
			TotalRecords:    system.System.Events.Meta.TotalRecords,
			Error:           errMessage,
			EventTimestamps: eventTimestamps,
		})
		ctr++
	}
}

func BuildGetSystemEventsConfiguration(event nuclio.Event) *GetSystemEventsConfiguration {
	var systemEventsConfiguration GetSystemEventsConfiguration

	paginationStr := event.GetFieldString("severity")
	lastEventsAmount := event.GetFieldString("last_events_amount")

	systemEventsConfiguration.Filters = buildFilters(event)

	pagination, _ := strconv.ParseBool(paginationStr)
	systemEventsConfiguration.Pagination = pagination
	systemEventsConfiguration.ShowLastEvents = false

	if lastEventsAmount != "" {
		systemEventsConfiguration.ShowLastEvents = true

		lastEventsAmountInt, _ := strconv.ParseInt(lastEventsAmount, 10, 8)
		systemEventsConfiguration.ShowLastEventsLength = int(lastEventsAmountInt)
	}
	return &systemEventsConfiguration
}

func getSystemEvents(context *nuclio.Context,
	provazioSystem ProvazioSystem,
	getSystemEventsConfiguration *GetSystemEventsConfiguration,
	systemsChannel chan<- SystemChannelResponse) {
	userData := context.UserData.(UserData)
	system := System{
		ProvazioSystem:               provazioSystem,
		Credentials:                  userData.SystemCredentials,
		Port:                         userData.SystemApiPort,
		GetSystemEventsConfiguration: getSystemEventsConfiguration,
	}
	context.Logger.DebugWith("Getting events", "systemID", system.GetID())
	if systemEvents, err := system.GetEvents(); err != nil {
		context.Logger.ErrorWith("Fetch Error", "err", err)
		systemsChannel <- SystemChannelResponse{System: system, Error: err}
	} else {
		context.Logger.DebugWith("Done getting events", "systemID", system.GetID())
		system.Events = *systemEvents
		systemsChannel <- SystemChannelResponse{System: system, Error: nil}
	}
}

func buildFilters(event nuclio.Event) map[string]string {
	filters := make(map[string]string)

	eventKind := event.GetFieldString("kind")
	eventSeverity := event.GetFieldString("severity")
	eventDescription := event.GetFieldString("description")
	eventVisibility := event.GetFieldString("visibility")
	if eventKind != "" {
		filters["kind"] = eventKind
	}

	if eventSeverity != "" {
		filters["severity"] = eventSeverity
	}

	if eventDescription != "" {
		filters["description"] = eventDescription
	}

	if eventVisibility != "" {
		filters["visibility"] = eventVisibility
	}

	return filters
}

// Provazio
type Provazio struct {
	appName   string
	useRemote bool
	env       string
}

// Provazio GET /api/systems response
type ProvazioSystem struct {
	Meta struct {
		ID string `json:"id,omitempty"`
	} `json:"meta,omitempty"`
	Spec struct {
		Description string `json:"description,omitempty"`
	} `json:"spec,omitempty"`
	Status struct {
		State   string `json:"state,omitempty"`
		Tenants []struct {
			Meta struct {
				ID string `json:"id,omitempty"`
			} `json:"meta,omitempty"`
			Status struct {
				Services struct {
					Dashboard struct {
						URLs map[string]string
					} `json:"dashboard,omitempty"`
				} `json:"services,omitempty"`
			} `json:"status,omitempty"`
		} `json:"tenants,omitempty"`
	} `json:"status,omitempty"`
}

func NewProvazio(userData *UserData, event nuclio.Event) *Provazio {
	provazioEnv := event.GetFieldString("provazio_env")
	if provazioEnv == "" {
		provazioEnv = userData.ProvazioEnv
	}

	UseRemote := true
	provazioUseRemote := event.GetFieldString("provazio_use_remote")
	if provazioUseRemote == "" {
		UseRemote = userData.ProvazioUserRemote
	} else {
		UseRemote = provazioUseRemote == "true"
	}
	return &Provazio{
		env:       provazioEnv,
		useRemote: UseRemote,
	}
}

func (p Provazio) GetSystems() ([]ProvazioSystem, error) {
	var response []byte
	client, err := createHTTPClient()
	if err != nil {
		return nil, err
	}

	res, err := client.Get(p.getAPISystemsURL())
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, errors.Errorf("Could not fetch systems, status: %d", res.StatusCode)
	}
	defer res.Body.Close() // nolint: errcheck

	if response, err = ioutil.ReadAll(res.Body); err != nil {
		return nil, errors.Wrap(err, "Failed to read response body")
	}

	var systems []ProvazioSystem
	if err := json.Unmarshal(response, &systems); err != nil {
		return nil, errors.Wrap(err, "Failed to deserialize Provazio API response")
	}

	var readySystems []ProvazioSystem
	for _, system := range systems {
		if system.Status.State == "ready" {

			// Allow only ready systems
			readySystems = append(readySystems, system)
		}
	}
	return readySystems, nil
}

func (p Provazio) getAPISystemsURL() string {
	url := ""
	switch p.env {
	case "trial":
		if p.useRemote {
			url = "https://dashboard.trial.provazio.iguazio.com"
		} else {
			url = "http://provazio-dashboard:8060"
		}
		break
	case "prod":
		if p.useRemote {
			url = "https://dashboard.prod.provazio.iguazio.com"
		} else {
			url = "http://provazio-dashboard-customer:8060"
		}
		break
	case "dev":
		if p.useRemote {
			url = "https://dashboard.dev.provazio.iguazio.com"
		} else {
			url = "http://provazio-dashboard:8060"
		}
		break
	default:
		return ""
	}
	return fmt.Sprintf("%s/api/systems", url)
}

// Iguazio System
type SystemCredentials struct {
	Username string
	Password string
}

type System struct {
	ProvazioSystem               ProvazioSystem
	Events                       Events
	Port                         int
	Credentials                  SystemCredentials
	GetSystemEventsConfiguration *GetSystemEventsConfiguration
}

type Events struct {
	Meta struct {
		Ctx          string `json:"ctx,omitempty"`
		TotalRecords int    `json:"total_records"`
	} `json:"meta,omitempty"`
	Data []struct {
		Attributes struct {
			Kind             string `json:"kind,omitempty"`
			Description      string `json:"description,omitempty"`
			Visibility       string `json:"visibility,omitempty"`
			Classification   string `json:"classification,omitempty"`
			Source           string `json:"source,omitempty"`
			TimestampIso8601 string `json:"timestamp_iso8601,omitempty"`
			SystemEvent      bool   `json:"system_event,omitempty"`
			Severity         string `json:"severity,omitempty"`
		} `json:"attributes,omitempty"`
		ID string `json:"id,omitempty"`
	} `json:"data,omitempty"`
}

func (s System) GetID() string {
	return s.ProvazioSystem.Meta.ID
}

func (s System) GetURL() string {
	for _, tenant := range s.ProvazioSystem.Status.Tenants {
		if tenant.Meta.ID == "default-tenant" {
			return tenant.Status.Services.Dashboard.URLs["https"]
		}
	}
	return ""
}

func (s System) GetApiBaseUrl() string {
	return fmt.Sprintf("https://%s", s.GetURL())
}

func (s System) GetEvents() (*Events, error) {

	eventsUrl := fmt.Sprintf("%s/api/events", s.GetURL())

	client, err := s.createClient()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, eventsUrl, nil)
	q := req.URL.Query()
	for k, v := range s.GetSystemEventsConfiguration.Filters {
		q.Add(fmt.Sprintf("filter[%s]", k), v)
	}
	q.Add("pagination", strconv.FormatBool(s.GetSystemEventsConfiguration.Pagination))
	q.Add("count", "records")
	q.Add("sort", "-timestamp_iso8601")
	req.URL.RawQuery = q.Encode()
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to perform get events request")
	}
	if res.StatusCode != http.StatusOK {
		return nil, errors.Errorf("Failed to fetch events, system: %s, status: %d",
			s.GetID(),
			res.StatusCode)
	}
	defer res.Body.Close() // nolint: errcheck

	responseBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read response body")
	}
	var events Events
	if err := json.Unmarshal(responseBody, &events); err != nil {
		return nil, errors.Wrap(err, "Failed to deserialize API response")
	}
	return &events, nil
}

func (s System) createClient() (*http.Client, error) {
	client, err := createHTTPClient()
	if err != nil {
		return nil, err
	}
	loginUrl := fmt.Sprintf("%s/api/sessions", s.GetURL())

	loginBodyTemplate := `{
"data": {"type": "session", "attributes": { "username": "%s", "password": "%s", "plane": "control"}}
}`
	loginBodyStr := fmt.Sprintf(loginBodyTemplate, s.Credentials.Username, s.Credentials.Password)

	var loginBodyRequest = []byte(loginBodyStr)
	res, err := client.Post(loginUrl, "application/json", bytes.NewBuffer(loginBodyRequest))
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusCreated {
		return nil, errors.Errorf("Failed to login system: %s, status: %d",
			s.GetID(),
			res.StatusCode)
	}
	return client, nil
}

// Common
func createHTTPClient() (*http.Client, error) {
	timeout := time.Second * 25
	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		return nil, err
	}
	client := http.Client{
		Timeout: timeout,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	return &client, nil
}
