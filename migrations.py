from sqlalchemy import create_engine, text
from database import SQLALCHEMY_DATABASE_URL

def run_migrations():
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
    
    with engine.connect() as connection:
        # Add OAuth columns to users table
        connection.execute(text("""
            ALTER TABLE users 
            ADD COLUMN oauth_provider VARCHAR;
        """))
        
        connection.execute(text("""
            ALTER TABLE users 
            ADD COLUMN oauth_id VARCHAR;
        """))
        
        connection.execute(text("""
            ALTER TABLE users 
            ADD COLUMN oauth_data JSON;
        """))
        
        connection.commit()

if __name__ == "__main__":
    run_migrations() 