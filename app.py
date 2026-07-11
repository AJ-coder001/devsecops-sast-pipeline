import os

# TEST VULNERABILITIES (for scanner verification)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
db_password = "Super_seCret_PaSsword123"

def run_query(user_input):
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '%s'" % user_input
    db.execute(query)

    def ping_host(host):
        # Vulnerable to command injection
        os.system(f"ping -c 1 {host}")
