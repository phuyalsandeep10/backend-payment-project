#!/usr/bin/env python3
"""
Simple script to restart Django development server
"""

import os
import sys
import subprocess
import signal
import time

def find_django_processes():
    """Find running Django development server processes"""
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        django_processes = []
        
        for line in lines:
            if 'manage.py runserver' in line and 'python' in line:
                parts = line.split()
                if len(parts) > 1:
                    pid = int(parts[1])
                    django_processes.append(pid)
        
        return django_processes
    except Exception as e:
        print(f"Error finding Django processes: {e}")
        return []

def kill_django_processes():
    """Kill existing Django server processes"""
    processes = find_django_processes()
    for pid in processes:
        try:
            print(f"Killing Django process {pid}")
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
        except ProcessLookupError:
            print(f"Process {pid} already terminated")
        except Exception as e:
            print(f"Error killing process {pid}: {e}")

def start_django_server():
    """Start Django development server"""
    try:
        print("Starting Django development server...")
        # Change to backend directory
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        os.chdir(backend_dir)
        
        # Start server in background
        subprocess.Popen(['python', 'manage.py', 'runserver', '0.0.0.0:8001'])
        print("Django server started on http://0.0.0.0:8001")
        
    except Exception as e:
        print(f"Error starting Django server: {e}")

if __name__ == "__main__":
    print("Restarting Django development server...")
    kill_django_processes()
    time.sleep(2)  # Give processes time to terminate
    start_django_server()
    print("Django server restart completed!")