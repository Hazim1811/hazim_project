from django.contrib.admin import AdminSite
from django.urls import path
from django.conf import settings
from django.http import HttpResponse
from django.utils.html import escape
from django.utils.timezone import localtime
from django.contrib.admin.views.decorators import staff_member_required

import os


@staff_member_required
def activity_log_view(request):
    log_path = os.path.join(settings.BASE_DIR, 'activity.log')
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            lines = f.readlines()

        # Reverse order (latest first)
        lines = lines[::-1]

        # Format into table rows
        table_rows = ''
        for line in lines:
            parts = line.strip().split("] ", 1)
            if len(parts) == 2:
                tag = parts[0][1:]  # remove opening [
                message = escape(parts[1])
                table_rows += f"<tr><td>{escape(tag)}</td><td>{message}</td></tr>"
            else:
                table_rows += f"<tr><td colspan='2'>{escape(line.strip())}</td></tr>"

        return HttpResponse(f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    background-color: #1e1e1e;
                    color: #f0f0f0;
                }}
                .back-btn {{
                    background-color: #3c8dbc;
                    padding: 8px 14px;
                    color: white;
                    text-decoration: none;
                    border-radius: 6px;
                    font-weight: bold;
                    display: inline-block;
                    margin-bottom: 20px;
                }}
                .back-btn:hover {{
                    background-color: #367fa9;
                }}
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin-top: 10px;
                }}
                th, td {{
                    border: 1px solid #444;
                    padding: 8px;
                    text-align: left;
                }}
                th {{
                    background-color: #333;
                }}
                tr:nth-child(even) {{ background-color: #2a2a2a; }}
                h2 {{
                    margin-top: 0;
                }}
            </style>
        </head>
        <body>
            <a href="/admin/" class="back-btn">← Back to Admin</a>
            <h2>Activity Log Viewer</h2>
            <table>
                <tr><th>Event Type</th><th>Details</th></tr>
                {table_rows}
            </table>
        </body>
        </html>
        """)
    return HttpResponse("<h2>No activity log found.</h2>")