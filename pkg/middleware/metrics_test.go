package middleware

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func newMetricsApp() *fiber.App {
	app := fiber.New()
	app.Use(NewMetrics())
	app.Get("/metrics", MetricsHandler())
	app.Get("/api/v1/auth/users/:id", func(c *fiber.Ctx) error { return c.SendString("ok") })
	return app
}

func scrapeMetrics(t *testing.T, app *fiber.App) string {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest("GET", "/metrics", nil))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// กับดักที่ทำให้ Prometheus ระเบิด: id ที่อยู่ใน path ทำให้ label แตกไม่จำกัด
func TestRouteLabelUsesPatternNotRawPath(t *testing.T) {
	app := newMetricsApp()
	for _, id := range []string{"aaa", "bbb", "ccc"} {
		if _, err := app.Test(httptest.NewRequest("GET", "/api/v1/auth/users/"+id, nil)); err != nil {
			t.Fatal(err)
		}
	}

	body := scrapeMetrics(t, app)
	if !strings.Contains(body, `route="/api/v1/auth/users/:id"`) {
		t.Errorf("ไม่พบ label ที่เป็น pattern ของ route:\n%s", body)
	}
	for _, id := range []string{"aaa", "bbb", "ccc"} {
		if strings.Contains(body, "/api/v1/auth/users/"+id) {
			t.Errorf("id %q หลุดเข้าไปเป็น label — label จะแตกไม่จำกัด", id)
		}
	}
}

// path ที่ไม่ตรง route ไหนเลยต้องยุบเป็น unmatched
// ไม่งั้นคนยิงสุ่ม path มั่วๆ ก็ทำให้ label แตกได้เหมือนกัน
func TestUnmatchedPathsCollapse(t *testing.T) {
	app := newMetricsApp()
	for _, p := range []string{"/nope", "/also-nope", "/still-nope"} {
		if _, err := app.Test(httptest.NewRequest("GET", p, nil)); err != nil {
			t.Fatal(err)
		}
	}

	body := scrapeMetrics(t, app)
	if !strings.Contains(body, `route="unmatched"`) {
		t.Errorf("path ที่ไม่ match ควรยุบเป็น unmatched:\n%s", body)
	}
	if strings.Contains(body, `route="/nope"`) {
		t.Error("path ที่ไม่ match หลุดเข้าไปเป็น label")
	}
}

// /metrics ไม่ควรนับตัวเอง ไม่งั้นกราฟจะมี traffic พื้นหลังตลอดเวลา
// ทั้งที่ไม่มีผู้ใช้จริงเลย เพราะ Prometheus ยิงทุก 30 วินาที
func TestMetricsEndpointDoesNotCountItself(t *testing.T) {
	app := newMetricsApp()
	scrapeMetrics(t, app)
	body := scrapeMetrics(t, app)

	if strings.Contains(body, `route="/metrics"`) {
		t.Errorf("นับ /metrics ของตัวเองด้วย:\n%s", body)
	}
}

// ชื่อ metric ต้องตรงกับ service อื่น ไม่งั้น dashboard เดียวครอบทุก service ไม่ได้
func TestMetricNamesMatchTheOtherServices(t *testing.T) {
	app := newMetricsApp()
	if _, err := app.Test(httptest.NewRequest("GET", "/api/v1/auth/users/x", nil)); err != nil {
		t.Fatal(err)
	}

	body := scrapeMetrics(t, app)
	for _, name := range []string{
		"http_requests_total",
		"http_request_duration_seconds",
		"http_requests_in_flight",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("ไม่พบ metric %q — dashboard ที่ query ชื่อนี้จะไม่เห็น service นี้", name)
		}
	}
}
