# Описание

Скрипт для нагрузочного тестирования загрузки файлов Uploads 

Используемый стек: ```python3.7```, ```locustio0.9```, ```pyquery1.4```

# Установка

1. Создать и активировать виртуальную среду

    ```$ virtualenv -p python3.7 venv```
    
    ```$ source venv/bin/activate```

2. Установить зависимости

    ```$ pip install -r requirements.txt```

3. Сгенерировать файлы для загрузки

    ```$ mkdir files_to_upload ```
    
    ```$ python generate_files.py ``` 

3. Задать настройки приложения

    Настройки задаются в самом файле, необходимо задать id события в  ```event```.
    Логин и пароль задается в файле (нужно создать самостоятельно) ```credentials```, формат данных авторизации ```<login>:<password>```, каждая новая пара на новой строке.
    При логине через админку (**в текущей версии работоспособен только этот вариант**) формат данных выглядит как ``` admin:<login>:<password>```
    Данные могут быть вперемешку (обычный логин и логин админа).

# Запуск приложения

``` $ locust --host=<host> --no-web --csv <csv_file> -c <clients> -r <hatch_rate> -t <time> ```, где

```<host>``` - base-url хоста, который будем тестировать,
```<csv_file>``` - название (только имя) файла (а по факту файлов, их будет два), куда будут записаны результаты тестирования,
```<clients>``` - количество пользователей, которое будет сэмулировано,
```<hatch_rate>``` - количество пользователей в секунду, которое будет сэмулировано,
```<time>``` - время теста, в формате 1h30m или 5m
