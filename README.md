<h1 align="center">ISE Policy Grapher</h1>

A simple tool that will parse your exported ISE Policy XML file and translate it to a GraphML file that you can open with yEd (or others graphing tools) to visualize it. 

It will also help you to identify unused objects (disabled rules, unlinked conditions and authorization profiles) which can be cleaned. 

Compatible with all ISE versions >= 2.6. 

## Installation 

#### 1. Clone the repo to your working directory 
```bash
git clone https://github.com/AnthoBalitrand/ise-policy-grapher.git
```

#### 2. Create a virtual environment (optional) and activate it 
```bash
python3 -m venv ./venv
source venv/bin/activate
```

#### 3. Install requirements 
```bash
pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

## How to use it 

#### 1. Extract your ISE policy file 

Through the administration GUI, browse to Administration --> Backup & Restore --> Policy Export

Encrypted files are not supported. 

![alt text](doc/images/ise_export_page.png)

#### 2. Start the script with input file 

```bash
python3 ise_grapher.py ise_policy_file.xml 
```

#### 3. Output

Several files will be created in the "outputs" directory :

- <policy_name>.graphml for each policy of the policy set 
- global.graphml for the global view of all objects 

**<policy_name>.graphml** will display only objects used on the given policy (not orphan objects).

**global.graphml** will display all objects, including unused ones, to help for cleaning. 


## Visualization

You can open the generated files with yEd. 

For better visibility, use the "Radial" layout with default parameters : 

![alt text](doc/images/yed_radial_layout.png)

Here's an output example for a given policy : 

![alt_text](doc/images/example_policy_output.png)

Here's an output example for the global graph (notice the unused objects that can be clearly identified) : 

![alt_text](doc/images/global_policy_output.png)

## Objects types

### Policy object
![alt_text](doc/images/policy.png) 

### Active authentication rule 
![alt_text](doc/images/authen_rule_enabled.png)

### Disabled authentication rule 
(note that a * is prepended to the name)

![alt_text](doc/images/authen_rule_disabled.png)

### Active authorization rule 
![alt text](doc/images/author_rule_enabled.png)

### Disabled authorization rule
(note that a * is prepended to the name)

![alt_text](doc/images/author_rule_disabled.png)

### Default condition (Cisco provided) 
![alt_text](doc/images/default_condition.png)

### Custom condition 
![alt_text](doc/images/custom_condition.png)

### Default authorization profile (Cisco provided)
![alt_text](doc/images/default_authprofile.png)

### Custom authorization profile
![alt_text](doc/images/custom_authprofile.png)
