# Network Scanner
Royi and Danielle python firewall

# prerequisites
```bash
pip install -r requirements.txt
```

### MongoDB

Install mongodb locally - ``` https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-os-x/ ```

##### For MacOS

1. ```xcode-select --install```
2. ```brew tap mongodb/brew```
3. ```brew install mongodb-community@8.0```
4. ```brew services start mongodb-community@8.0```

Install Mongo DB GUI for local run - ``` https://www.mongodb.com/try/download/compass ```


### GUI
##### pyWebio

```pip3 install --use-pep517 pywebio```

##### pyQT

1. ```conda install pyqt```
2. ```brew install qt```
3. ```brew link --force qt```
3. ```export QT_PLUGIN_PATH=$(brew --prefix qt)/lib/qt/plugins```
4. ```conda create -n pyqt-env python=3.9 pyqt```
5. ```conda activate pyqt-env```





