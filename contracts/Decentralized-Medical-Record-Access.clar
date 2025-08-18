;; Error Codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-EXISTS (err u102))
(define-constant ERR-NOT-FOUND (err u103))

;; Admin variable
(define-data-var admin principal tx-sender)

;; Maps
(define-map patient-records
  principal
  {
    encrypted-data: (string-utf8 500),
    timestamp: uint,
    last-updated: uint
  }
)

(define-map access-grants
  {patient: principal, provider: principal}
  {
    granted-at: uint,
    expires-at: uint,
    access-level: uint
  }
)

(define-map provider-registry
  principal
  {
    name: (string-utf8 100),
    license: (string-utf8 50),
    active: bool
  }
)

(define-map audit-log
  {patient: principal, log-id: uint}
  {
    provider: principal,
    action: (string-ascii 50),
    timestamp: uint,
    success: bool
  }
)

(define-data-var next-log-id uint u1)

;; Read-only functions
(define-read-only (get-patient-record (patient principal))
  (match (map-get? patient-records patient)
    record (ok record)
    ERR-NOT-FOUND
  )
)

(define-read-only (check-access (provider principal) (patient principal))
  (match (map-get? access-grants {patient: patient, provider: provider})
    grant (ok grant)
    ERR-NOT-AUTHORIZED
  )
)

(define-read-only (get-provider-info (provider principal))
  (match (map-get? provider-registry provider)
    info (ok info)
    ERR-NOT-FOUND
  )
)

(define-read-only (get-audit-entry (patient principal) (log-id uint))
  (map-get? audit-log {patient: patient, log-id: log-id}))

(define-read-only (get-latest-audit-entries (patient principal) (count uint))
  (let ((current-id (var-get next-log-id)))
    (if (> current-id count)
      (fold append-audit-entry (list u1 u2 u3 u4 u5 u6 u7 u8 u9 u10) (list))
      (list))))

(define-private (append-audit-entry (offset uint) (acc (list 10 (optional {provider: principal, action: (string-ascii 50), timestamp: uint, success: bool}))))
  (let ((current-id (var-get next-log-id)))
    (if (> current-id offset)
      (unwrap-panic (as-max-len? (append acc (map-get? audit-log {patient: tx-sender, log-id: (- current-id offset)})) u10))
      acc)))

(define-private (log-audit-event (patient principal) (provider principal) (action (string-ascii 50)) (success bool))
  (let ((log-id (var-get next-log-id)))
    (begin
      (map-set audit-log 
        {patient: patient, log-id: log-id}
        {
          provider: provider,
          action: action,
          timestamp: stacks-block-height,
          success: success
        })
      (var-set next-log-id (+ log-id u1))
      log-id)))

;; Write functions
(define-public (add-medical-record (encrypted-data (string-utf8 500)))
  (if (is-some (map-get? patient-records tx-sender))
    ERR-ALREADY-EXISTS
    (ok (map-set patient-records tx-sender
      {
        encrypted-data: encrypted-data,
        timestamp: stacks-block-height,
        last-updated: stacks-block-height
      }))
  )
)

(define-public (update-medical-record (encrypted-data (string-utf8 500)))
  (match (map-get? patient-records tx-sender)
    record (ok (map-set patient-records tx-sender
      {
        encrypted-data: encrypted-data,
        timestamp: (get timestamp record),
        last-updated: stacks-block-height
      }))
    ERR-NOT-FOUND
  )
)

(define-public (grant-access (provider principal) (expires-at uint) (access-level uint))
  (begin
    (asserts! (is-some (map-get? provider-registry provider)) ERR-NOT-AUTHORIZED)
    (let ((provider-info (unwrap-panic (map-get? provider-registry provider))))
      (asserts! (get active provider-info) ERR-NOT-AUTHORIZED)
      (asserts! (> expires-at stacks-block-height) (err u105))
      (log-audit-event tx-sender provider "grant-access" true)
      (ok (map-set access-grants 
        {patient: tx-sender, provider: provider}
        {
          granted-at: stacks-block-height,
          expires-at: expires-at,
          access-level: access-level
        }))
    )
  )
)


(define-public (revoke-access (provider principal))
  (begin
    (log-audit-event tx-sender provider "revoke-access" true)
    (ok (map-delete access-grants {patient: tx-sender, provider: provider}))))

(define-public (register-provider (name (string-utf8 100)) (license (string-utf8 50)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
    (asserts! (is-none (map-get? provider-registry tx-sender)) ERR-ALREADY-EXISTS)
    (ok (map-set provider-registry tx-sender {
      name: name,
      license: license,
      active: true
    }))
  )
)

(define-public (deactivate-provider (provider principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
    (match (map-get? provider-registry provider)
      info
      (ok (map-set provider-registry provider {
        name: (get name info),
        license: (get license info),
        active: false
      }))
      ERR-NOT-FOUND
    )
  )
)


(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq new-admin tx-sender)) (err u107)) ;; prevent transferring to self
    (ok (var-set admin new-admin))
  )
)
;;