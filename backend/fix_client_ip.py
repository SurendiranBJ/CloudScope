import os

def fix_client_ip(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    modified = False
    
    # Replace in routers
    old_line = 'client_ip = getattr(request.state, "client_ip", None) or (request.client.host if request.client else None)'
    new_line = 'client_ip = getattr(request.state, "client_ip", None) or (request.client.host if request.client else None)'
    
    if old_line in content:
        content = content.replace(old_line, new_line)
        modified = True
    
    # Replace in rate limiter
    old_line2 = '''            client_ip = getattr(request.state, "client_ip", None) or (request.client.host if request.client else "unknown")'''
    new_line2 = '''            client_ip = getattr(request.state, "client_ip", None) or (request.client.host if request.client else "unknown")'''
    
    if old_line2 in content:
        content = content.replace(old_line2, new_line2)
        modified = True
        
    if modified:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f'Fixed {filepath}')

for root, _, files in os.walk('c:/Users/surab/Desktop/CloudScope/backend'):
    for file in files:
        if file.endswith('.py'):
            fix_client_ip(os.path.join(root, file))
