from app.main import app
from fastapi.routing import APIRoute

print("All routes in app:")
for r in app.routes:
    if isinstance(r, APIRoute):
        print(f"  {list(r.methods)} {r.path}")
    else:
        print(f"  [OTHER] {type(r).__name__}")
