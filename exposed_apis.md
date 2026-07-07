# Food Delivery Ecosystem - Complete API Reference

This document provides a highly detailed reference of all exposed APIs in the Food Delivery Microservices ecosystem. It is intended for UI developers (and AI UI Generators) to build client applications (Customer App, Restaurant Dashboard, Delivery Executive App) without needing to inspect backend code.

---

## 1. Global Concepts and Conventions
All requests interacting with protected endpoints must pass through the `ApiGateway` on port `8080`.

### 1.1 Authentication
The system uses stateless JWTs.
* **Header:** `Authorization: Bearer <token>`
* The API Gateway intercepts this header, validates the signature using the IdentityService public key, and strips it.
* The Gateway injects internal downstream headers (`X-User-Id`, `X-User-Phone`, `X-User-Roles`). **The UI should NOT send these `X-User-*` headers directly, as they will be sanitized and ignored.**

### 1.2 Client Traceability, Metadata & Observability Headers
To assist with debugging, tracking, and security monitoring, the UI (Web, iOS, Android) **MUST** include the following metadata headers on all API requests:
* `X-Request-Id` / `X-Correlation-Id`: (UUID) A uniquely generated UUID for every single API request. Used to trace the request as it jumps across microservices.
* `X-Device-Id`: (String) A unique, persistent identifier for the user's physical device/browser installation.
* `X-App-Version`: (String) The version of the client app (e.g., `1.4.2`).
* `X-Client-Platform`: (String) The platform making the request (`Web`, `iOS`, `Android`).
* `X-Device-Model`: (String) Hardware model (e.g., `iPhone 15 Pro`, `Pixel 8`, `Chrome Windows`).
* `X-OS-Version`: (String) Operating System version (e.g., `iOS 17.4`, `Android 14`).
* `User-Agent`: (String) Standard browser or app user agent string.

### 1.3 Role-Based Access Control (RBAC)

### 1.4 Image & Media Uploads
Currently, the system is in active development, and a final CDN/Storage integration (e.g., AWS S3, Cloudinary) has not yet been finalized. 
* **Current Behavior:** The frontend UI should provide standard dummy URL strings (e.g., `"https://example.com/logo.png"`) in the JSON body for all image fields (`logoUrl`, `bannerUrl`, `imageUrl`, `photoUrl`). The backend will accept and persist these.
* **Future Behavior:** Once the CDN is implemented, the UI will likely use a Presigned URL flow or a dedicated `POST /api/v1/media/upload` endpoint to upload the raw file to the CDN first, receive the final public URL, and *then* pass that URL in the JSON body of the standard API requests.

### Standard Response Format
Unless otherwise specified, all endpoints return a standard `ApiResponse<T>` wrapper:
```json
{
  "success": true, 
  "message": "Human readable success or error message",
  "data": { ... payload ... },
  "timestamp": "2026-07-07T12:00:00.000Z"
}
```

---

## 1. Identity & Authentication (Identity Service)

### 1.1 Initiate Login (OTP)
Used by clients to request an OTP.
* **Endpoint:** `POST /api/v1/internal/auth/initiate`
* **Headers:** 
  * `X-Calling-Service`: The name of the client app (e.g. `CUSTOMER_APP`)
* **Query Parameters:**
  * `phoneNumber` (String, required): e.g. "9999999999"
* **Response:** `ApiResponse<String>` (OTP sent successfully)

### 1.2 Verify OTP
* **Endpoint:** `POST /api/v1/internal/auth/verify`
* **Headers:** 
  * `X-Calling-Service`: The name of the client app (e.g. `CUSTOMER_APP`)
* **Query Parameters:**
  * `phoneNumber` (String, required)
  * `otp` (String, required)
* **Response:** `ApiResponse<String>` - The `data` field contains the JWT token.

### 1.3 Manage User Roles
* **Get users by role:** `GET /api/v1/internal/users/by-role?roleName={role}`
* **Assign Role:** `POST /api/v1/internal/users/{id}/roles`
  * **Body:** `{"roleName": "CUSTOMER"}`
* **Remove Role:** `DELETE /api/v1/internal/users/{id}/roles/{roleName}`

---

## 2. Customer Application APIs

### 2.1 Order Management
* **Create Order:** `POST /api/v1/orders`
  * **Headers:** `Authorization: Bearer <jwt_token>` (Requires `CUSTOMER`)
  * **Body:**
    ```json
    {
      "customerId": "uuid",
      "restaurantId": "uuid",
      "deliveryAddressId": "uuid",
      "items": [
        { "menuItemId": "uuid", "quantity": 2 }
      ]
    }
    ```
  * **Response:** `ApiResponse<OrderResponse>`
    ```json
    {
      "success": true,
      "message": "Order created successfully",
      "data": {
        "id": "uuid",
        "customerId": "uuid",
        "restaurantId": "uuid",
        "status": "CREATED",
        "totalAmount": 300.0,
        "items": [],
        "createdAt": "2026-07-07T12:00:00Z",
        "paymentIntent": "order_razorpay_12345" // Crucial for UI to initialize payment gateway
      },
      "timestamp": "2026-07-07T12:00:00Z"
    }
    ```
* **Approve/Reject Delayed ETA:** `POST /api/v1/orders/{orderId}/delay-approval`
  * **Headers:** `Authorization: Bearer <jwt_token>`
  * **Body:** `{"approved": true}`
* **Live Order Tracking:** `GET /api/v1/orders/{orderId}/live-tracking`
  * **Headers:** `Authorization: Bearer <jwt_token>`
  * **Produces:** `text/event-stream` (Server-Sent Events)

### 2.2 Customer Addresses
* **Add Address:** `POST /api/v1/customers/{customerId}/addresses`
  * **Headers:** `Authorization: Bearer <jwt_token>`
  * **Body:**
    ```json
    {
      "label": "Home",
      "addressLine1": "123 Main St",
      "addressLine2": "Apt 4B",
      "city": "Bangalore",
      "state": "KA",
      "zipCode": "560001",
      "latitude": 12.9716,
      "longitude": 77.5946
    }
    ```
* **List Addresses:** `GET /api/v1/customers/{customerId}/addresses`

### 2.3 Discovery & Geocoding
* **Nearby Restaurants:** `GET /api/v1/restaurants/nearby?lat=12.97&lng=77.59&radius=5.0`
* **Check Delivery Availability:** `GET /api/v1/restaurants/{restaurantId}/delivery-availability?lat=12.97&lng=77.59`
* **Autocomplete Places:** `GET /api/v1/places/autocomplete?query=Koraman&lat=12.97&lng=77.59`
* **Reverse Geocode:** `GET /api/v1/places/reverse-geocode?lat=12.97&lng=77.59`

---

## 3. Restaurant Application APIs

### 3.1 Onboarding & Outlets
* **Create Brand:** `POST /api/v1/brands`
  * **Headers:** `Authorization: Bearer <jwt_token>` (Requires `RESTAURANT`)
  * **Body:**
    ```json
    {
      "name": "KFC",
      "gstin": "123456789012345",
      "pan": "ABCDE1234F",
      "cin": "U12345MH2023PTC123456",
      "bankAccountNumber": "1234567890",
      "ifscCode": "HDFC0001234",
      "logoUrl": "https://example.com/logo.png"
    }
    ```
* **Create Outlet:** `POST /api/v1/brands/{brandId}/outlets`
  * **Headers:** `Authorization: Bearer <jwt_token>`
  * **Body:**
    ```json
    {
      "name": "KFC Indiranagar",
      "fssaiLicenseNumber": "12345678901234",
      "lat": 12.9716,
      "lng": 77.5946,
      "openingTime": "09:00:00",
      "closingTime": "23:00:00",
      "bannerUrl": "https://example.com/banner.png"
    }
    ```
* **List Brand Outlets:** `GET /api/v1/brands/{brandId}/outlets`
* **Get Outlet Details:** `GET /api/v1/restaurants/{restaurantId}`

### 3.2 Catalog Management
* **Add Master Menu Item:** `POST /api/v1/brands/{brandId}/master-menu`
  * **Headers:** `Authorization: Bearer <jwt_token>`
  * **Body:** `{"name": "Zinger Burger", "basePrice": 150.0, "defaultPrepTimeMinutes": 15, "imageUrl": "https://example.com/item.png"}`
* **Get Master Menu:** `GET /api/v1/brands/{brandId}/master-menu`
* **Override Menu Item (Price/Availability at Outlet):** `POST /api/v1/outlets/{outletId}/menu-overrides/{masterMenuItemId}`
  * **Body:** `{"price": 160.0, "active": true}`
* **Get Effective Outlet Catalog:** `GET /api/v1/restaurants/{restaurantId}/catalog/items`
* **Get Menu Items in Batch:** `GET /api/v1/restaurants/{restaurantId}/menu/batch?ids=uuid1,uuid2`

### 3.3 Order Fulfillment (Kitchen Display System)
* **Accept Order:** `POST /api/v1/restaurants/{restaurantId}/fulfillment/orders/{orderId}/accept`
  * **Headers:** `Authorization: Bearer <jwt_token>` (Requires Outlet Owner)
  * **Body (Optional):** `{"additionalPrepTime": 5, "delayReason": "Kitchen busy"}`
* **Reject Order:** `POST /api/v1/restaurants/{restaurantId}/fulfillment/orders/{orderId}/reject`
* **Mark Order Ready:** `POST /api/v1/restaurants/{restaurantId}/fulfillment/orders/{orderId}/ready`
* **Cancel Order (After Accept):** `POST /api/v1/restaurants/{restaurantId}/fulfillment/orders/{orderId}/cancel`

---

## 4. Delivery Executive APIs

### 4.1 Onboarding & Status
* **Onboard Executive:** `POST /api/delivery/onboard`
  * **Headers:** `Authorization: Bearer <jwt_token>` (Requires `DELIVERY`)
  * **Body:** `{"name": "John Doe", "phoneNumber": "8888888888", "vehicleNumber": "KA01AB1234", "photoUrl": "https://example.com/photo.png"}`
* **Update Availability:** `POST /api/delivery/status`
  * **Headers:** `Authorization: Bearer <jwt_token>`
  * **Body:** `{"driverId": "uuid", "available": true}`

### 4.2 Order Management
* **Accept Delivery:** `POST /api/delivery/drivers/{driverId}/orders/{orderId}/accept`
* **Reject Delivery Ping:** `POST /api/delivery/drivers/{driverId}/orders/{orderId}/reject`
* **Update Delivery Status:** `POST /api/delivery/drivers/{driverId}/orders/{orderId}/status`
  * **Headers:** `Authorization: Bearer <jwt_token>`
  * **Body:** `{"status": "PICKED_UP"}` (Valid values: `PICKED_UP`, `DELIVERED`)
* **Handle Timeout:** `POST /api/delivery/drivers/{driverId}/orders/{orderId}/timeout`

### 4.3 Telemetry & Logistics
* **Batch Telemetry Sync:** `POST /api/v1/delivery/telemetry/batch`
  * **Headers:** `Authorization: Bearer <jwt_token>`
  * **Body:**
    ```json
    [
      {
        "driverId": "uuid",
        "lat": 12.9716,
        "lng": 77.5946,
        "timestamp": "2026-07-07T12:00:00Z"
      }
    ]
    ```
* **Logistics Route:** `GET /api/v1/logistics/route?origin_lat=12.9&origin_lng=77.5&dest_lat=12.95&dest_lng=77.6`

---

## 5. Third-Party Webhooks

These endpoints are typically not called by standard UI clients, but by external integrations.
* **Payment Webhooks:** 
  * `POST /api/v1/webhooks/razorpay`
  * `POST /api/v1/webhooks/cashfree`
  * `POST /api/v1/webhooks/vyapar`
* **SMS Webhooks:**
  * `POST /webhooks/providers/exotel/status` (Consumes: `application/x-www-form-urlencoded`)

## 6. Real-Time Connections (WebSockets & SSE)

For real-time features like driver tracking and live map updates, the ecosystem supports both Server-Sent Events (SSE) and WebSockets.

### 6.1 Customer Live Order Tracking (SSE)
Instead of polling for order status, the Customer Application should connect to the Server-Sent Events stream to get live GPS updates of the delivery executive.
* **Endpoint:** `GET /api/v1/orders/{orderId}/live-tracking`
* **Headers:** `Authorization: Bearer <jwt_token>` (Requires `CUSTOMER`)
* **Produces:** `text/event-stream`
* **Behavior:** Once connected, the server will push JSON objects containing the driver's current `lat` and `lng` as they move.

### 6.2 Delivery Executive Telemetry Stream (WebSocket)
While the Delivery App *can* use the HTTP `/api/v1/delivery/telemetry/batch` endpoint, it is highly recommended to use the WebSocket for lower latency and less battery drain.
* **Endpoint:** `ws://<gateway-url>/api/delivery/ws/telemetry`
* **Authentication:** The JWT token must be provided. (Typically via a query parameter `?token=<jwt_token>` during the WebSocket handshake).
* **Behavior:** Once connected, the Delivery App should continuously push JSON payloads representing the driver's coordinates.
  ```json
  {
    "driverId": "uuid",
    "orderId": "uuid",
    "lat": 12.9716,
    "lng": 77.5946
  }
  ```
