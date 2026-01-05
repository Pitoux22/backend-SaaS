
from fastapi import FastAPI
from typing import Union
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean , ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from fastapi import Depends,HTTPException
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer

# Cela indique à FastAPI que le token se récupère via l'URL "/token" que nous venons de créer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == token).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return user
# 1. La connexion (Ici SQLite pour la simplicité, mais identique pour PostgreSQL)
SQLALCHEMY_DATABASE_URL = "sqlite:///./saas.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 2. Le Modèle SQLAlchemy (La représentation de la Table)
class ProjectModel(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("UserModel", back_populates="projects")
class UserModel(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    projects = relationship("ProjectModel", back_populates="owner")
# 3. Création des tables dans la base de données
Base.metadata.create_all(bind=engine)

class Project(BaseModel):
    name: str
    description: Union[str, None] = None
    is_active: bool = True
class ProjectResponse(Project):
    id: int
    name: str
    description: Union[str, None] = None
    is_active: bool = True
    class Config:
        from_attributes = True
class UserCreate(BaseModel):
    email: str
    password: str
class UserResponse(BaseModel):
    id: int
    email: str
    class Config:
        from_attributes = True
class Token(BaseModel):
    access_token: str
    token_type: str
app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "SaaS World"}


@app.post("/projects/")
def create_project(project: Project,db: Session = Depends(get_db),current_user: UserModel = Depends(get_current_user)):
    new_project = ProjectModel(**project.model_dump(),owner_id=current_user.id)

    db.add(new_project)
    db.commit()
    db.refresh(new_project)
    return new_project

@app.get("/projects/",response_model=list[ProjectResponse],)
def read_projects( db: Session = Depends(get_db),current_user: UserModel = Depends(get_current_user)):

    project = db.query(ProjectModel).filter(ProjectModel.owner_id == current_user.id).all()
    return project

@app.get("/projects/{project_id}",response_model=ProjectResponse)
def read_project(project_id: int, db: Session = Depends(get_db)):   
     
    project = db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project
@app.put("/projects/{project_id}",response_model=ProjectResponse)
def update_project(project_id: int, updated_project: Project, db: Session = Depends(get_db),current_user: UserModel = Depends(get_current_user)):
    project = db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this project")
    for key, value in updated_project.model_dump().items():
        setattr(project, key, value)
    
    db.commit()
    db.refresh(project)
    return project
@app.delete("/projects/{project_id}")
def delete_project(project_id: int, db: Session = Depends(get_db),current_user: UserModel = Depends(get_current_user)):
    project = db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this project")

    db.delete(project)
    db.commit()
    return {"detail": "Project deleted successfully"}

@app.post("/users/",response_model=UserResponse)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(UserModel).filter(UserModel.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    fake_hashed_password = user.password + "notreallyhashed"
    db_user = UserModel(email=user.email, hashed_password=fake_hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == form_data.username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    fake_hashed_password = form_data.password + "notreallyhashed"
    if not user.hashed_password == fake_hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.email, "token_type": "bearer"}