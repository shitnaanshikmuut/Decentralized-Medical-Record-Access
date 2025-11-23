;; Error Codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-EXISTS (err u102))
(define-constant ERR-NOT-FOUND (err u103))
(define-constant ERR-INVALID-DURATION (err u104))
(define-constant ERR-DELEGATION-EXISTS (err u108))
(define-constant ERR-NOT-DELEGATE (err u109))

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

(define-map emergency-access
  {patient: principal, provider: principal}
  {
    granted-at: uint,
    expires-at: uint,
    justification: (string-utf8 200)
  }
)

(define-map delegations
  {patient: principal, delegate: principal}
  {
    granted-at: uint,
    expires-at: uint,
    can-grant: bool,
    can-revoke: bool,
    active: bool
  }
)

(define-data-var next-log-id uint u1)
(define-data-var emergency-duration uint u144)
(define-data-var max-versions uint u10)

(define-map record-versions
  {patient: principal, version: uint}
  {
    encrypted-data: (string-utf8 500),
    timestamp: uint,
    previous-version: uint
  }
)

(define-map version-metadata
  principal
  {
    current-version: uint,
    total-versions: uint
  }
)

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

(define-read-only (check-emergency-access (provider principal) (patient principal))
  (match (map-get? emergency-access {patient: patient, provider: provider})
    grant (if (> (get expires-at grant) stacks-block-height)
            (ok grant)
            ERR-NOT-AUTHORIZED)
    ERR-NOT-AUTHORIZED))

(define-read-only (get-emergency-duration)
  (var-get emergency-duration))

(define-read-only (get-delegation (patient principal) (delegate principal))
  (match (map-get? delegations {patient: patient, delegate: delegate})
    delegation (ok delegation)
    ERR-NOT-FOUND))

(define-read-only (is-valid-delegate (patient principal) (delegate principal))
  (match (map-get? delegations {patient: patient, delegate: delegate})
    delegation (ok (and (get active delegation) (> (get expires-at delegation) stacks-block-height)))
    (ok false)))

(define-read-only (get-latest-audit-entries (patient principal) (count uint))
  (let ((current-id (var-get next-log-id)))
    (if (> current-id count)
      (fold append-audit-entry (list u1 u2 u3 u4 u5 u6 u7 u8 u9 u10) (list))
      (list))))

(define-read-only (get-record-version (patient principal) (version uint))
  (match (map-get? record-versions {patient: patient, version: version})
    record (ok record)
    ERR-NOT-FOUND))

(define-read-only (get-version-metadata (patient principal))
  (match (map-get? version-metadata patient)
    metadata (ok metadata)
    ERR-NOT-FOUND))

(define-read-only (get-version-history (patient principal))
  (match (map-get? version-metadata patient)
    metadata (ok (get total-versions metadata))
    (ok u0)))

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
    (begin
      (map-set patient-records tx-sender
        {
          encrypted-data: encrypted-data,
          timestamp: stacks-block-height,
          last-updated: stacks-block-height
        })
      (map-set record-versions
        {patient: tx-sender, version: u1}
        {
          encrypted-data: encrypted-data,
          timestamp: stacks-block-height,
          previous-version: u0
        })
      (map-set version-metadata tx-sender
        {
          current-version: u1,
          total-versions: u1
        })
      (ok true))
  )
)

(define-public (update-medical-record (encrypted-data (string-utf8 500)))
  (match (map-get? patient-records tx-sender)
    record 
    (let ((metadata (unwrap! (map-get? version-metadata tx-sender) ERR-NOT-FOUND))
          (current-ver (get current-version metadata))
          (total-vers (get total-versions metadata))
          (new-version (+ current-ver u1)))
      (asserts! (<= new-version (var-get max-versions)) (err u111))
      (map-set patient-records tx-sender
        {
          encrypted-data: encrypted-data,
          timestamp: (get timestamp record),
          last-updated: stacks-block-height
        })
      (map-set record-versions
        {patient: tx-sender, version: new-version}
        {
          encrypted-data: encrypted-data,
          timestamp: stacks-block-height,
          previous-version: current-ver
        })
      (map-set version-metadata tx-sender
        {
          current-version: new-version,
          total-versions: (+ total-vers u1)
        })
      (log-audit-event tx-sender tx-sender "record-version-created" true)
      (ok true))
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

(define-public (grant-access-as-delegate (patient principal) (provider principal) (expires-at uint) (access-level uint))
  (begin
    (asserts! (is-some (map-get? provider-registry provider)) ERR-NOT-AUTHORIZED)
    (let ((provider-info (unwrap-panic (map-get? provider-registry provider)))
          (delegation (unwrap! (map-get? delegations {patient: patient, delegate: tx-sender}) ERR-NOT-DELEGATE)))
      (asserts! (get active provider-info) ERR-NOT-AUTHORIZED)
      (asserts! (get active delegation) ERR-NOT-DELEGATE)
      (asserts! (get can-grant delegation) ERR-NOT-AUTHORIZED)
      (asserts! (> (get expires-at delegation) stacks-block-height) ERR-NOT-DELEGATE)
      (asserts! (> expires-at stacks-block-height) (err u105))
      (log-audit-event patient tx-sender "delegate-grant-access" true)
      (ok (map-set access-grants 
        {patient: patient, provider: provider}
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

(define-public (revoke-access-as-delegate (patient principal) (provider principal))
  (begin
    (let ((delegation (unwrap! (map-get? delegations {patient: patient, delegate: tx-sender}) ERR-NOT-DELEGATE)))
      (asserts! (get active delegation) ERR-NOT-DELEGATE)
      (asserts! (get can-revoke delegation) ERR-NOT-AUTHORIZED)
      (asserts! (> (get expires-at delegation) stacks-block-height) ERR-NOT-DELEGATE)
      (log-audit-event patient tx-sender "delegate-revoke-access" true)
      (ok (map-delete access-grants {patient: patient, provider: provider})))))

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
    (asserts! (not (is-eq new-admin tx-sender)) (err u107))
    (ok (var-set admin new-admin))
  )
)

(define-public (request-emergency-access (patient principal) (justification (string-utf8 200)))
  (begin
    (asserts! (is-some (map-get? provider-registry tx-sender)) ERR-NOT-AUTHORIZED)
    (let ((provider-info (unwrap-panic (map-get? provider-registry tx-sender))))
      (asserts! (get active provider-info) ERR-NOT-AUTHORIZED)
      (asserts! (is-none (map-get? emergency-access {patient: patient, provider: tx-sender})) ERR-ALREADY-EXISTS)
      (let ((expires-at (+ stacks-block-height (var-get emergency-duration))))
        (log-audit-event patient tx-sender "emergency-access-requested" true)
        (ok (map-set emergency-access 
          {patient: patient, provider: tx-sender}
          {
            granted-at: stacks-block-height,
            expires-at: expires-at,
            justification: justification
          }))))))

(define-public (revoke-emergency-access (provider principal))
  (begin
    (asserts! (is-some (map-get? emergency-access {patient: tx-sender, provider: provider})) ERR-NOT-FOUND)
    (log-audit-event tx-sender provider "emergency-access-revoked" true)
    (ok (map-delete emergency-access {patient: tx-sender, provider: provider}))))

(define-public (set-emergency-duration (new-duration uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
    (asserts! (and (>= new-duration u1) (<= new-duration u2016)) ERR-INVALID-DURATION)
    (ok (var-set emergency-duration new-duration))))

(define-public (add-delegate (delegate principal) (expires-at uint) (can-grant bool) (can-revoke bool))
  (begin
    (asserts! (not (is-eq tx-sender delegate)) (err u110))
    (asserts! (> expires-at stacks-block-height) ERR-INVALID-DURATION)
    (asserts! (is-none (map-get? delegations {patient: tx-sender, delegate: delegate})) ERR-DELEGATION-EXISTS)
    (log-audit-event tx-sender delegate "delegation-granted" true)
    (ok (map-set delegations
      {patient: tx-sender, delegate: delegate}
      {
        granted-at: stacks-block-height,
        expires-at: expires-at,
        can-grant: can-grant,
        can-revoke: can-revoke,
        active: true
      }))))

(define-public (revoke-delegation (delegate principal))
  (begin
    (let ((delegation (unwrap! (map-get? delegations {patient: tx-sender, delegate: delegate}) ERR-NOT-FOUND)))
      (log-audit-event tx-sender delegate "delegation-revoked" true)
      (ok (map-set delegations
        {patient: tx-sender, delegate: delegate}
        {
          granted-at: (get granted-at delegation),
          expires-at: (get expires-at delegation),
          can-grant: (get can-grant delegation),
          can-revoke: (get can-revoke delegation),
          active: false
        })))))

(define-public (update-delegation-permissions (delegate principal) (can-grant bool) (can-revoke bool))
  (begin
    (let ((delegation (unwrap! (map-get? delegations {patient: tx-sender, delegate: delegate}) ERR-NOT-FOUND)))
      (asserts! (get active delegation) ERR-NOT-FOUND)
      (log-audit-event tx-sender delegate "delegation-updated" true)
      (ok (map-set delegations
        {patient: tx-sender, delegate: delegate}
        {
          granted-at: (get granted-at delegation),
          expires-at: (get expires-at delegation),
          can-grant: can-grant,
          can-revoke: can-revoke,
          active: true
        })))))

(define-public (rollback-to-version (version uint))
  (let ((metadata (unwrap! (map-get? version-metadata tx-sender) ERR-NOT-FOUND))
        (version-data (unwrap! (map-get? record-versions {patient: tx-sender, version: version}) ERR-NOT-FOUND))
        (current-record (unwrap! (map-get? patient-records tx-sender) ERR-NOT-FOUND)))
    (asserts! (<= version (get total-versions metadata)) ERR-NOT-FOUND)
    (map-set patient-records tx-sender
      {
        encrypted-data: (get encrypted-data version-data),
        timestamp: (get timestamp current-record),
        last-updated: stacks-block-height
      })
    (map-set version-metadata tx-sender
      {
        current-version: version,
        total-versions: (get total-versions metadata)
      })
    (log-audit-event tx-sender tx-sender "record-rollback" true)
    (ok version)))

(define-public (set-max-versions (new-max uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
    (asserts! (and (>= new-max u1) (<= new-max u50)) ERR-INVALID-DURATION)
    (ok (var-set max-versions new-max))))
;;
