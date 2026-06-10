package main

import (
	"fmt"
)

const DecoyHTML = `
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Under Maintenance</title>
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #fafafa; color: #333; }
		.card { text-align: center; padding: 40px; background: white; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); max-width: 400px; }
		h1 { font-size: 24px; margin-bottom: 16px; }
		p { color: #666; line-height: 1.5; }
		.loader { border: 3px solid #f3f3f3; border-top: 3px solid #3498db; border-radius: 50%; width: 30px; height: 30px; animation: spin 2s linear infinite; margin: 20px auto; }
		@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
	</style>
</head>
<body>
	<div class="card">
		<div class="loader"></div>
		<h1>Технические работы</h1>
		<p>На ресурсе проводятся плановые технические работы. Пожалуйста, зайдите позже.</p>
	</div>
</body>
</html>
`

var DecoyHTTPResponse = fmt.Sprintf("HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(DecoyHTML), DecoyHTML)

