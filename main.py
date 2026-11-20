import datetime
import random
from collections import defaultdict

class HRSystemMonitor:
    def __init__(self, normal_working_hours=(9, 17)):
        """
        Initializes the HR System Monitor with predefined 'normal' parameters.
        These parameters represent learned 'normal' behavior, akin to a simple AI model
        that identifies baselines for user activity.
        """
        self.normal_working_hours = normal_working_hours  # (start_hour, end_hour)
        self.known_users = set()
        # Stores distinct departments accessed by each user during the simulation
        self.user_distinct_departments = defaultdict(set)

    def add_known_user(self, user_id):
        self.known_users.add(user_id)

    def analyze_log_entry(self, log_entry):
        """
        Analyzes a single log entry for anomalies based on predefined rules.
        This simulates a basic AI-driven anomaly detection system.
        ""
        user = log_entry['user']
        timestamp = log_entry['timestamp']
        department = log_entry['department']
        anomalies = []

        # Anomaly 1: Unknown User Access
        # AI systems often flag access from unrecognised entities.
        if user not in self.known_users:
            anomalies.append(f"UNKNOWN_USER: User '{user}' is not a recognized system user.")
            # In a real system, this might trigger an alert and then potentially add the user
            # to a watchlist or a 'pending review' list. For this demo, we add them to known_users
            # after the first detection to avoid repeated alerts for the same new user.
            self.add_known_user(user)

        # Anomaly 2: Access outside normal working hours
        # AI can learn typical access patterns (e.g., time of day) and flag deviations.
        access_hour = timestamp.hour
        if not (self.normal_working_hours[0] <= access_hour < self.normal_working_hours[1]):
            anomalies.append(f"UNUSUAL_TIME: Access by '{user}' at {timestamp.strftime('%H:%M')} (outside normal hours).")

        # Anomaly 3: Broad Access to many distinct departments
        # AI can detect unusual breadth of access, which might indicate privilege escalation or reconnaissance.
        self.user_distinct_departments[user].add(department)
        # Arbitrary threshold: more than 3 distinct departments accessed by a user is suspicious
        if len(self.user_distinct_departments[user]) > 3:
            anomalies.append(f"BROAD_ACCESS: User '{user}' accessed {len(self.user_distinct_departments[user])} distinct departments (high diversity).")

        return anomalies

# --- Simulation Data Setup ---
known_users = ['alice', 'bob', 'charlie']
departments = ['HR_Payroll', 'HR_Recruitment', 'HR_Benefits', 'IT_Support', 'Finance_Ops']

def generate_log_entry(user, hour, minute, department):
    return {
        'user': user,
        'timestamp': datetime.datetime(2023, 10, 26, hour, minute, 0),
        'department': department
    }

# Simulate normal activity
normal_logs = [
    generate_log_entry('alice', 9, 30, 'HR_Payroll'),
    generate_log_entry('bob', 10, 15, 'HR_Recruitment'),
    generate_log_entry('charlie', 11, 0, 'HR_Benefits'),
    generate_log_entry('alice', 14, 0, 'HR_Payroll'),
    generate_log_entry('bob', 15, 45, 'HR_Recruitment'),
]

# Simulate suspicious activity (ARTEX-like scenarios)
suspicious_logs = [
    # Anomaly 1: Unknown user attempting access
    generate_log_entry('attacker_x', 10, 0, 'HR_Payroll'),
    # Anomaly 2: Known user accessing outside working hours
    generate_log_entry('alice', 23, 0, 'HR_Benefits'),
    # Anomaly 3: Known user accessing many departments quickly (broad access simulation)
    generate_log_entry('bob', 13, 0, 'HR_Payroll'),
    generate_log_entry('bob', 13, 5, 'HR_Recruitment'),
    generate_log_entry('bob', 13, 10, 'HR_Benefits'),
    generate_log_entry('bob', 13, 15, 'IT_Support'),
    generate_log_entry('bob', 13, 20, 'Finance_Ops'),
    # Combined anomalies: Unknown user, outside hours, broad access
    generate_log_entry('attacker_y', 2, 30, 'IT_Support'),
    generate_log_entry('attacker_y', 2, 40, 'HR_Payroll'),
    generate_log_entry('attacker_y', 2, 50, 'HR_Benefits'),
    generate_log_entry('attacker_y', 3, 0, 'Finance_Ops'),
]

# --- Monitor Initialization and Simulation ---
monitor = HRSystemMonitor()
for user in known_users:
    monitor.add_known_user(user)

print("--- Simulating HR System Access Monitoring ---")
print("This script demonstrates a basic anomaly detection system, similar to how AI might detect")
print("suspicious activity in an HR system, potentially preventing incidents like the ARTEX attack.")
print("-" * 60)

all_logs = normal_logs + suspicious_logs
# Sort logs by timestamp to process them chronologically
all_logs.sort(key=lambda x: x['timestamp'])

for i, log in enumerate(all_logs):
    print(f"\nProcessing Log #{i+1}: {log['user']} accessed {log['department']} at {log['timestamp'].strftime('%Y-%m-%d %H:%M')}")
    anomalies = monitor.analyze_log_entry(log)
    if anomalies:
        print("  !!! ANOMALY DETECTED !!!")
        for anomaly in anomalies:
            print(f"  - {anomaly}")
    else:
        print("  - No anomalies detected.")

print("\n" + "-" * 60)
print("Simulation complete. Anomalies highlighted indicate potential security threats.")
