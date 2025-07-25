---
layout: post
title: 'Setting the Redirect URI when Spring Boot running behind a proxy server'
date: 2025-07-25 14:11:00 +0700
categories: [spring-boot, spring-security, reverse-proxy]
---

Rất hay — bạn đã phân tích đúng:
✔️ `server.forward-headers-strategy=native` **hoạt động tốt** nếu container hỗ trợ (Tomcat, Jetty, Undertow)
✔️ Và bạn thấy `scheme`, `host`, `port` trả về đúng trong controller ⇒ chứng tỏ reverse proxy **gửi đúng `X-Forwarded-*`** và Spring Boot **đã xử lý đúng**

---

## ❓ CÂU HỎI CỦA BẠN

> Liệu **với `native`**, có cách chính thức nào để Spring Security OAuth2 Client sinh đúng `redirect-uri` không?

### 👉 **Câu trả lời là:**

> **CÓ**, nếu và chỉ nếu:
>
> * Servlet container hỗ trợ xử lý header proxy ở tầng thấp (đúng)
> * Và proxy **không xóa hoặc override sai** các header

Nhưng **có điều kiện bổ sung đặc biệt**:

---

## 🔍 ĐIỂM GIỚI HẠN CỦA `native` (cần hiểu rõ)

Spring Boot với `native` **không tự đăng ký `ForwardedHeaderFilter`**, mà phụ thuộc vào:

* Servlet container (Tomcat) xử lý `X-Forwarded-*` theo chuẩn Servlet 4+
* **Không mặc định xử lý `X-Forwarded-Prefix`**, cái rất quan trọng nếu bạn chạy reverse proxy có prefix như `/app`

➡️ **Với OAuth2 redirect**, nếu bạn chạy trên root `/`, và proxy không rewrite prefix, thì `native` vẫn hoạt động tốt.

---

## ✅ CÁCH CHÍNH THỨC ĐỂ DÙNG `native` CHUẨN CHO OAUTH2 CLIENT

### 1. **Đảm bảo Servlet container xử lý proxy headers đúng**

Spring Boot mặc định dùng Tomcat embedded, và từ Servlet 4.0+ đã hỗ trợ các header proxy (`Forwarded` hoặc `X-Forwarded-*`)
\=> ✅ Không cần thêm filter nếu proxy chuẩn

---

### 2. **Cấu hình Nginx chuẩn (nếu bạn dùng Nginx)**

```nginx
location / {
    proxy_pass http://localhost:8080;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    # ⛔ Không cấu hình X-Forwarded-Prefix nếu bạn không rewrite path
}
```

➡️ Tránh dùng `/app` prefix nếu bạn không config đầy đủ (hoặc cấu hình `context-path`)

---

### 3. **Dùng redirect-uri template chính xác**

Ví dụ:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          myclient:
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
```

➡️ Với `native`, nếu proxy headers được xử lý đúng thì `{baseUrl}` sẽ **tự động phản ánh scheme, host, port đúng**

---

### 4. **KHÔNG dùng `X-Forwarded-Prefix` nếu không có context-path**

Vì `native` **không xử lý `X-Forwarded-Prefix`** (Spring chỉ làm điều đó khi dùng `framework`, qua `ForwardedHeaderFilter`)

➡️ Nếu bạn muốn `/app` hoạt động đúng:

* Đặt `server.servlet.context-path=/app`
* Và trong proxy:

```nginx
location /app/ {
    proxy_pass http://localhost:8080/app/;
}
```

---

## ✅ TÓM LẠI – CẤU HÌNH CHUẨN CHO `native`

| Thành phần                 | Cấu hình                                             |
| -------------------------- | ---------------------------------------------------- |
| Spring Boot                | `server.forward-headers-strategy=native`             |
| Tomcat (embedded)          | Mặc định OK                                          |
| Proxy                      | Gửi đủ `X-Forwarded-Proto`, `X-Forwarded-Host`, v.v. |
| redirect-uri               | Sử dụng `{baseUrl}/...`                              |
| Không dùng prefix (`/app`) | hoặc cấu hình `context-path=/app` và proxy tương ứng |

---

## ✳️ Khi nên chuyển sang `framework`?

| Trường hợp                                           | Có nên dùng `framework`? |
| ---------------------------------------------------- | ------------------------ |
| Dùng `/app` prefix nhưng không muốn đổi context-path | ✅ Nên                    |
| Muốn xử lý `X-Forwarded-Prefix` tự động              | ✅ Nên                    |
| Có nhiều proxy không tiêu chuẩn                      | ✅ Nên                    |
| Dùng reverse proxy đơn giản, không rewrite path      | ❌ Không cần (native OK)  |

---

Nếu bạn cung cấp reverse proxy cụ thể (có dùng `/app` không), mình có thể kiểm tra cấu hình redirect cụ thể giúp. Bạn đang dùng `context-path`, hay chỉ reverse proxy trên `/app`?
