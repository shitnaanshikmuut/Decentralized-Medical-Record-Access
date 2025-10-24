# 🏥 Decentralized Medical Record Access

## 🌟 Overview
A secure and decentralized solution for managing medical records on the Stacks blockchain. Patients maintain full control over their medical data while being able to grant and revoke access to healthcare providers.

## ✨ Features
- 🔐 Encrypted medical record storage
- 👨‍⚕️ Provider registration and verification
- 🎫 Granular access control
- ⏱️ Time-based access grants
- 🔄 Record updates and management

## 🚀 Getting Started

### Prerequisites
- Clarinet
- Stacks wallet

### 📋 Contract Functions

#### For Patients
- `add-medical-record`: Add new medical records
- `update-medical-record`: Update existing records
- `grant-access`: Grant provider access
- `revoke-access`: Revoke provider access

#### For Providers
- `register-provider`: Register as healthcare provider
- `get-patient-record`: Access patient records
- `check-access`: Verify access permissions

#### For Administrators
- `deactivate-provider`: Suspend provider access
- `transfer-admin`: Transfer admin rights

## 🔧 Usage Example
```clarity
;; Add medical record
(contract-call? .medical-records add-medical-record "encrypted-data-hash")

;; Grant access to provider
(contract-call? .medical-records grant-access 'PROVIDER-ADDRESS u100 u1)
```

## 🤝 Contributing
Contributions welcome! Please read our contributing guidelines first.

## 📜 License
MIT
```