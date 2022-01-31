# Prereqs

- All instances must be provisioned and licensed
- Admin level access tokens must be generated for all instances except coverity
- Coverity instances require admin username and password
- User names and emails must be collected manually or using the downloadable template
- Wherever you run this app from, must be able to communicate with any instances you are trying to create credentials for

# How To

1. `git clone https://github.com/shanko07/synopsys-instance-creator.git`
2. `pip install -r requirements.txt`
3. `python app.py`
4. Open [the site](http://localhost:5000)

![UI](./ui.png)

To use the utility you simply "Add" whichever Synopsys servers you'd like to add users to with the accompanying admin
credentials on those servers. Then you "Add" the users.  You can also add users by downloading the template and filling in the necessary information and uploading back using the "Browse" button.  The utility will automatically generate passwords, create the
users as admins, and prompt you to download an excel sheet named `Credentials.xlsx`

:warning: The contents of `Credentials.xlsx` are plaintext usernames and passwords for admin users. Please be careful
with this file. :warning:
