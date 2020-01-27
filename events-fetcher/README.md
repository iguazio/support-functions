# Get Events

## Goal
Get events from provazio systems using platform's Events API


## Flow
1. Get provazio systems via `<provazioURL>/api/systems`
2. Create filters by the request's query string
3. For-each system, fetch its events by the create filters  
 3.1. If error occured, response the error as well (e.g: Could not login\ TimeOut)
4. Aggregate results, and json-response to user 


## Contributing

1. Ensure you have go@1.11+
2. `cd github.com/devops-functions/get-events`
3. `go mod download`
4. Enable `Go Module Integration` on GoLang
2. Development should be on `github.com/get-events/main.go` 


> This function should be deployed within provazio environment