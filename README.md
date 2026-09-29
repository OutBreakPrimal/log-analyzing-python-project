# log-analyzing-python-project
A lightweight Python tool that scans SSH authentication logs and web server access logs for signs of attack and produces a severity-ranked report mapped to MITRE ATT&CK.

Built with the Python standard library only, so there is nothing to install.
Quick start
#1 create the logs (these are synthetic)
python generate_sample_logs.py

#2. Analyze them
python loganalyzer.py sample_logs/auth.log sample_logs/access.log

#3. Optionally save the results
python loganalyzer.py sample_logs/auth.log sample_logs/access.log \
    --json findings.json --markdown report.md
(Python 3.8 is required for aforementioned to work)
here are some examples how the code works:
<img width="1281" height="1010" alt="Снимок экрана (346)" src="https://github.com/user-attachments/assets/a8d7837e-cbd2-43c6-8651-1d406a1097ac" />
<img width="1277" height="993" alt="Снимок экрана (347)" src="https://github.com/user-attachments/assets/321cd09c-3778-4739-9c11-e2e2cef88126" />
<img width="1222" height="997" alt="Снимок экрана (348)" src="https://github.com/user-attachments/assets/4c646c20-977b-4cf6-8aa8-34669b58648b" />
