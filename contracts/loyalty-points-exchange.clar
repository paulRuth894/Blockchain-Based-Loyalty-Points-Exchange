;; ============================================================================
;; LOYALTY POINTS EXCHANGE SYSTEM
;; ============================================================================
;; A comprehensive blockchain-based loyalty points exchange system that enables
;; interoperable rewards transfer between merchants with built-in fraud prevention,
;; exchange rate mechanisms, and expiration management.

;; ============================================================================
;; CONSTANTS & ERROR CODES
;; ============================================================================

(define-constant CONTRACT_OWNER tx-sender)
(define-constant EXCHANGE_FEE u50) ;; 0.5% fee in basis points

;; Error codes
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_MERCHANT_NOT_FOUND (err u101))
(define-constant ERR_INSUFFICIENT_BALANCE (err u102))
(define-constant ERR_INVALID_AMOUNT (err u103))
(define-constant ERR_POINTS_EXPIRED (err u104))
(define-constant ERR_EXCHANGE_RATE_NOT_SET (err u105))
(define-constant ERR_MERCHANT_SUSPENDED (err u106))
(define-constant ERR_DAILY_LIMIT_EXCEEDED (err u107))
(define-constant ERR_SUSPICIOUS_ACTIVITY (err u108))
(define-constant ERR_INVALID_EXPIRATION (err u109))
(define-constant ERR_MERCHANT_EXISTS (err u110))

;; ============================================================================
;; DATA STRUCTURES
;; ============================================================================

;; Merchant registration and configuration
(define-map merchants
  { merchant-id: (string-ascii 32) }
  {
    owner: principal,
    name: (string-ascii 64),
    exchange-rate: uint, ;; Rate to base points (1 base = x merchant points)
    expiration-period: uint, ;; Blocks until expiration
    daily-limit: uint, ;; Max points per day per user
    suspended: bool,
    created-at: uint
  }
)

;; User point balances per merchant
(define-map user-balances
  { user: principal, merchant-id: (string-ascii 32) }
  {
    balance: uint,
    last-updated: uint,
    earned-today: uint,
    last-activity-block: uint
  }
)

;; Point expiration tracking
(define-map point-expirations
  { user: principal, merchant-id: (string-ascii 32), expiration-block: uint }
  { amount: uint }
)

;; Exchange transactions for audit trail
(define-map exchange-history
  { tx-id: uint }
  {
    from-user: principal,
    to-user: (optional principal),
    from-merchant: (string-ascii 32),
    to-merchant: (string-ascii 32),
    from-amount: uint,
    to-amount: uint,
    fee-amount: uint,
    timestamp: uint,
    exchange-type: (string-ascii 20) ;; "transfer", "exchange", "redeem"
  }
)

;; Fraud detection data
(define-map user-activity
  { user: principal }
  {
    daily-exchanges: uint,
    last-reset-block: uint,
    total-exchanges: uint,
    suspicious-flags: uint
  }
)

;; System configuration
(define-data-var next-tx-id uint u1)
(define-data-var system-suspended bool false)
(define-data-var max-daily-exchanges uint u10)
(define-data-var suspicious-threshold uint u3)

;; ============================================================================
;; MERCHANT MANAGEMENT
;; ============================================================================

;; Register a new merchant program
(define-public (register-merchant
  (merchant-id (string-ascii 32))
  (name (string-ascii 64))
  (exchange-rate uint)
  (expiration-period uint)
  (daily-limit uint))
  (let ((existing-merchant (map-get? merchants { merchant-id: merchant-id })))
    (asserts! (is-none existing-merchant) ERR_MERCHANT_EXISTS)
    (asserts! (> exchange-rate u0) ERR_INVALID_AMOUNT)
    (asserts! (> expiration-period u0) ERR_INVALID_EXPIRATION)
    (asserts! (> daily-limit u0) ERR_INVALID_AMOUNT)

    (map-set merchants
      { merchant-id: merchant-id }
      {
        owner: tx-sender,
        name: name,
        exchange-rate: exchange-rate,
        expiration-period: expiration-period,
        daily-limit: daily-limit,
        suspended: false,
        created-at: stacks-block-height
      }
    )
    (ok merchant-id)
  )
)

;; Update merchant exchange rate (only merchant owner)
(define-public (update-exchange-rate
  (merchant-id (string-ascii 32))
  (new-rate uint))
  (let ((merchant (unwrap! (map-get? merchants { merchant-id: merchant-id }) ERR_MERCHANT_NOT_FOUND)))
    (asserts! (is-eq tx-sender (get owner merchant)) ERR_UNAUTHORIZED)
    (asserts! (> new-rate u0) ERR_INVALID_AMOUNT)

    (map-set merchants
      { merchant-id: merchant-id }
      (merge merchant { exchange-rate: new-rate })
    )
    (ok new-rate)
  )
)

;; Suspend/unsuspend merchant (only contract owner)
(define-public (set-merchant-suspension
  (merchant-id (string-ascii 32))
  (suspended bool))
  (let ((merchant (unwrap! (map-get? merchants { merchant-id: merchant-id }) ERR_MERCHANT_NOT_FOUND)))
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)

    (map-set merchants
      { merchant-id: merchant-id }
      (merge merchant { suspended: suspended })
    )
    (ok suspended)
  )
)

;; ============================================================================
;; POINTS MANAGEMENT
;; ============================================================================

;; Award points to user (only merchant owner)
(define-public (award-points
  (user principal)
  (merchant-id (string-ascii 32))
  (amount uint))
  (let (
    (merchant (unwrap! (map-get? merchants { merchant-id: merchant-id }) ERR_MERCHANT_NOT_FOUND))
    (current-balance (default-to
      { balance: u0, last-updated: u0, earned-today: u0, last-activity-block: u0 }
      (map-get? user-balances { user: user, merchant-id: merchant-id })
    ))
    (expiration-block (+ stacks-block-height (get expiration-period merchant)))
  )
    (asserts! (is-eq tx-sender (get owner merchant)) ERR_UNAUTHORIZED)
    (asserts! (not (get suspended merchant)) ERR_MERCHANT_SUSPENDED)
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)

    ;; Check daily limit
    (let ((daily-earned (if (is-eq (get last-activity-block current-balance) stacks-block-height)
                           (get earned-today current-balance)
                           u0)))
      (asserts! (<= (+ daily-earned amount) (get daily-limit merchant)) ERR_DAILY_LIMIT_EXCEEDED)

      ;; Update balance
      (map-set user-balances
        { user: user, merchant-id: merchant-id }
        {
          balance: (+ (get balance current-balance) amount),
          last-updated: stacks-block-height,
          earned-today: (+ daily-earned amount),
          last-activity-block: stacks-block-height
        }
      )

      ;; Set expiration
      (map-set point-expirations
        { user: user, merchant-id: merchant-id, expiration-block: expiration-block }
        { amount: amount }
      )

      (ok amount)
    )
  )
)

;; Check and clean expired points
(define-private (clean-expired-points
  (user principal)
  (merchant-id (string-ascii 32)))
  (let (
    (current-balance (default-to
      { balance: u0, last-updated: u0, earned-today: u0, last-activity-block: u0 }
      (map-get? user-balances { user: user, merchant-id: merchant-id })
    ))
  )
    ;; In a production system, this would iterate through expiration entries
    ;; For simplicity, we'll check if points are older than the expiration period
    (match (map-get? merchants { merchant-id: merchant-id })
      merchant (if (> (- stacks-block-height (get last-updated current-balance)) (get expiration-period merchant))
        (begin
          (map-set user-balances
            { user: user, merchant-id: merchant-id }
            (merge current-balance { balance: u0 })
          )
          u0
        )
        (get balance current-balance)
      )
      u0 ;; Return 0 if merchant not found
    )
  )
)

;; ============================================================================
;; EXCHANGE SYSTEM
;; ============================================================================

;; Exchange points between merchants
(define-public (exchange-points
  (from-merchant (string-ascii 32))
  (to-merchant (string-ascii 32))
  (amount uint))
  (let (
    (from-merchant-data (unwrap! (map-get? merchants { merchant-id: from-merchant }) ERR_MERCHANT_NOT_FOUND))
    (to-merchant-data (unwrap! (map-get? merchants { merchant-id: to-merchant }) ERR_MERCHANT_NOT_FOUND))
    (user-balance (clean-expired-points tx-sender from-merchant))
    (activity (default-to
      { daily-exchanges: u0, last-reset-block: u0, total-exchanges: u0, suspicious-flags: u0 }
      (map-get? user-activity { user: tx-sender })
    ))
  )
    (asserts! (not (var-get system-suspended)) ERR_UNAUTHORIZED)
    (asserts! (not (get suspended from-merchant-data)) ERR_MERCHANT_SUSPENDED)
    (asserts! (not (get suspended to-merchant-data)) ERR_MERCHANT_SUSPENDED)
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)
    (asserts! (>= user-balance amount) ERR_INSUFFICIENT_BALANCE)

    ;; Fraud detection
    (let ((daily-count (if (is-eq (get last-reset-block activity) stacks-block-height)
                          (get daily-exchanges activity)
                          u0)))
      (asserts! (< daily-count (var-get max-daily-exchanges)) ERR_DAILY_LIMIT_EXCEEDED)
      (asserts! (< (get suspicious-flags activity) (var-get suspicious-threshold)) ERR_SUSPICIOUS_ACTIVITY)

      ;; Calculate exchange amounts
      (let (
        (from-rate (get exchange-rate from-merchant-data))
        (to-rate (get exchange-rate to-merchant-data))
        (base-amount (/ amount from-rate))
        (to-amount (/ (* base-amount to-rate) u100))
        (fee (/ (* to-amount EXCHANGE_FEE) u10000))
        (final-amount (- to-amount fee))
        (tx-id (var-get next-tx-id))
      )
        ;; Update balances
        (map-set user-balances
          { user: tx-sender, merchant-id: from-merchant }
          (merge (unwrap-panic (map-get? user-balances { user: tx-sender, merchant-id: from-merchant }))
                 { balance: (- user-balance amount) })
        )

        (let ((to-balance (default-to
          { balance: u0, last-updated: u0, earned-today: u0, last-activity-block: u0 }
          (map-get? user-balances { user: tx-sender, merchant-id: to-merchant })
        )))
          (map-set user-balances
            { user: tx-sender, merchant-id: to-merchant }
            (merge to-balance {
              balance: (+ (get balance to-balance) final-amount),
              last-updated: stacks-block-height
            })
          )
        )

        ;; Record transaction
        (map-set exchange-history
          { tx-id: tx-id }
          {
            from-user: tx-sender,
            to-user: none,
            from-merchant: from-merchant,
            to-merchant: to-merchant,
            from-amount: amount,
            to-amount: final-amount,
            fee-amount: fee,
            timestamp: stacks-block-height,
            exchange-type: "exchange"
          }
        )

        ;; Update activity tracking
        (map-set user-activity
          { user: tx-sender }
          {
            daily-exchanges: (+ daily-count u1),
            last-reset-block: stacks-block-height,
            total-exchanges: (+ (get total-exchanges activity) u1),
            suspicious-flags: (get suspicious-flags activity)
          }
        )

        (var-set next-tx-id (+ tx-id u1))
        (ok { exchanged: final-amount, fee: fee })
      )
    )
  )
)

;; Transfer points to another user
(define-public (transfer-points
  (recipient principal)
  (merchant-id (string-ascii 32))
  (amount uint))
  (let (
    (merchant (unwrap! (map-get? merchants { merchant-id: merchant-id }) ERR_MERCHANT_NOT_FOUND))
    (sender-balance (clean-expired-points tx-sender merchant-id))
    (tx-id (var-get next-tx-id))
  )
    (asserts! (not (get suspended merchant)) ERR_MERCHANT_SUSPENDED)
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)
    (asserts! (>= sender-balance amount) ERR_INSUFFICIENT_BALANCE)

    ;; Update sender balance
    (map-set user-balances
      { user: tx-sender, merchant-id: merchant-id }
      (merge (unwrap-panic (map-get? user-balances { user: tx-sender, merchant-id: merchant-id }))
             { balance: (- sender-balance amount) })
    )

    ;; Update recipient balance
    (let ((recipient-balance (default-to
      { balance: u0, last-updated: u0, earned-today: u0, last-activity-block: u0 }
      (map-get? user-balances { user: recipient, merchant-id: merchant-id })
    )))
      (map-set user-balances
        { user: recipient, merchant-id: merchant-id }
        (merge recipient-balance {
          balance: (+ (get balance recipient-balance) amount),
          last-updated: stacks-block-height
        })
      )
    )

    ;; Record transaction
    (map-set exchange-history
      { tx-id: tx-id }
      {
        from-user: tx-sender,
        to-user: (some recipient),
        from-merchant: merchant-id,
        to-merchant: merchant-id,
        from-amount: amount,
        to-amount: amount,
        fee-amount: u0,
        timestamp: stacks-block-height,
        exchange-type: "transfer"
      }
    )

    (var-set next-tx-id (+ tx-id u1))
    (ok amount)
  )
)

;; ============================================================================
;; FRAUD PREVENTION
;; ============================================================================

;; Flag suspicious activity (only contract owner)
(define-public (flag-suspicious-activity
  (user principal)
  (increment uint))
  (let ((activity (default-to
    { daily-exchanges: u0, last-reset-block: u0, total-exchanges: u0, suspicious-flags: u0 }
    (map-get? user-activity { user: user })
  )))
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)

    (map-set user-activity
      { user: user }
      (merge activity { suspicious-flags: (+ (get suspicious-flags activity) increment) })
    )
    (ok (+ (get suspicious-flags activity) increment))
  )
)

;; Reset user flags (only contract owner)
(define-public (reset-user-flags
  (user principal))
  (let ((activity (default-to
    { daily-exchanges: u0, last-reset-block: u0, total-exchanges: u0, suspicious-flags: u0 }
    (map-get? user-activity { user: user })
  )))
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)

    (map-set user-activity
      { user: user }
      (merge activity { suspicious-flags: u0 })
    )
    (ok true)
  )
)

;; ============================================================================
;; READ-ONLY FUNCTIONS
;; ============================================================================

;; Get user balance for a merchant
(define-read-only (get-balance
  (user principal)
  (merchant-id (string-ascii 32)))
  (let ((balance-data (map-get? user-balances { user: user, merchant-id: merchant-id })))
    (match balance-data
      balance (ok (get balance balance))
      (ok u0)
    )
  )
)

;; Get merchant information
(define-read-only (get-merchant
  (merchant-id (string-ascii 32)))
  (map-get? merchants { merchant-id: merchant-id })
)

;; Get exchange transaction details
(define-read-only (get-exchange-history
  (tx-id uint))
  (map-get? exchange-history { tx-id: tx-id })
)

;; Get user activity data
(define-read-only (get-user-activity
  (user principal))
  (map-get? user-activity { user: user })
)

;; Calculate exchange preview
(define-read-only (preview-exchange
  (from-merchant (string-ascii 32))
  (to-merchant (string-ascii 32))
  (amount uint))
  (let (
    (from-merchant-data (map-get? merchants { merchant-id: from-merchant }))
    (to-merchant-data (map-get? merchants { merchant-id: to-merchant }))
  )
    (match from-merchant-data
      from-data (match to-merchant-data
        to-data (let (
          (from-rate (get exchange-rate from-data))
          (to-rate (get exchange-rate to-data))
          (base-amount (/ amount from-rate))
          (to-amount (/ (* base-amount to-rate) u100))
          (fee (/ (* to-amount EXCHANGE_FEE) u10000))
          (final-amount (- to-amount fee))
        )
          (ok {
            will-receive: final-amount,
            fee: fee,
            exchange-rate: (/ to-amount amount)
          })
        )
        ERR_MERCHANT_NOT_FOUND
      )
      ERR_MERCHANT_NOT_FOUND
    )
  )
)

;; ============================================================================
;; ADMIN FUNCTIONS
;; ============================================================================

;; Emergency system suspension
(define-public (set-system-suspension
  (suspended bool))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set system-suspended suspended)
    (ok suspended)
  )
)

;; Update system parameters
(define-public (update-system-params
  (max-exchanges uint)
  (suspicious-thresh uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set max-daily-exchanges max-exchanges)
    (var-set suspicious-threshold suspicious-thresh)
    (ok true)
  )
)
