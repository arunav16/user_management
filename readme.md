# FastAPI User Management – Submission Summary

## 🎯 Project Goal
Provide a secure, RESTful user‐management API with:
- **CRUD** on users (create/read/update/delete)
- **Email verification** for new sign-ups
- **JWT-based auth** with role-based access (“ADMIN”, “MANAGER”, “AUTHENTICATED”, “ANONYMOUS”)
- **Search & filtering** (by email/username substring, role, registration date, professional status)
- **Pagination & sorting** on list endpoints

## 🔧 Tech Stack
- **FastAPI** – async web framework  
- **SQLAlchemy (async)** – PostgreSQL ORM  
- **Pydantic** – request/response models & validation  
- **python-jose** – JWT creation & parsing  
- **pytest + httpx** – async test suite with 92%+ coverage  
- **uvicorn** – ASGI server  


## 🚀 Key Highlights
- **Role-guarded endpoints** via a `require_role([...])` dependency  
- **Email workflows**: generate & persist `verification_token`, send email, verify via `/verify-email/{id}/{token}`  
- **Flexible CRUD**: administrators and managers can manage users; others get `403`  
- **Search & filter**: query parameters + SQLAlchemy dynamic filters  
- **Pagination links**: HATEOAS-style “self/first/next/last” in every list response  
- **Extensive tests**: cover happy paths and edge cases (invalid UUIDs, missing fields, auth failures, filters, sorting, pagination)  

## 🚑 Running Locally
1. **Install**: `pip install -r requirements.txt`  
2. **Migrate DB** (Alembic)  
3. **Start server**: `uvicorn app.main:app --reload`  
4. **Run tests**: `pytest --asyncio-mode=auto --cov=app`

---

👍 _This project delivers a complete, production-ready user management service with high test coverage and clean architecture._

