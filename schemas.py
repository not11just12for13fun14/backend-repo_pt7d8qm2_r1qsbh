"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

# SaaS: Email breach checker schemas

class Breach(BaseModel):
    name: str = Field(..., description="Breach name")
    domain: Optional[str] = Field(None, description="Domain affected")
    breachDate: Optional[str] = Field(None, description="Date of breach (YYYY-MM-DD)")
    addedDate: Optional[str] = Field(None, description="Date added to database")
    pwnCount: Optional[int] = Field(None, description="Number of accounts affected")
    description: Optional[str] = Field(None, description="Description of the breach")
    dataClasses: Optional[List[str]] = Field(default_factory=list, description="Types of data exposed")
    isVerified: Optional[bool] = Field(None, description="Verified by source")

class Check(BaseModel):
    """
    Email breach check records
    Collection name: "check"
    """
    email: str = Field(..., description="Email address checked")
    found: bool = Field(False, description="Whether any breaches were found")
    count: int = Field(0, description="Number of breaches found")
    breaches: List[Breach] = Field(default_factory=list, description="List of breaches (if any)")
    source: str = Field("hibp", description="Source used for lookup")
    is_demo: bool = Field(False, description="True if using demo/mock data")
    checked_at: datetime = Field(default_factory=datetime.utcnow, description="When the check occurred")

# Example schemas kept for reference (not used by app)
class User(BaseModel):
    name: str
    email: str
    address: str
    age: Optional[int] = None
    is_active: bool = True

class Product(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    category: str
    in_stock: bool = True

# Add your own schemas here:
# --------------------------------------------------

# Note: The Flames database viewer will automatically:
# 1. Read these schemas from GET /schema endpoint
# 2. Use them for document validation when creating/editing
# 3. Handle all database operations (CRUD) directly
# 4. You don't need to create any database endpoints!
