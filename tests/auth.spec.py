import pytest, datetime
from flask import json
from flask_jwt_extended import decode_token
from app import create_app, db
from app.database import User

@pytest.fixture
def app():
    app = create_app()
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()




# Unit Testing

def test_token_generation(client):
    response = client.post('/auth/register', json={
        'userId': '400',
        'firstName': 'John',
        'lastName': 'Cena',
        'email': 'Tohn.Cena@example.com',
        'password': 'password',
        'phone': '1234567890'
    })

    data = response.get_json()
    access_token = data['data']['accessToken']
    decoded_token = decode_token(access_token)
    assert 'sub' in decoded_token
    assert decoded_token['sub']['userId'] == 400



def test_token_expiry(client):
    response = client.post('/auth/register', json={
        'userId': '400',
        'firstName': 'John',
        'lastName': 'Cena',
        'email': 'Tohn.Cena@example.com',
        'password': 'password',
        'phone': '1234567890'
    })

    data = response.get_json()
    access_token = data['data']['accessToken'] 
    decoded_token = decode_token(access_token)
    assert 'exp' in decoded_token
    expiration_time = datetime.datetime.fromtimestamp(decoded_token['exp'])
    assert expiration_time > datetime.datetime.utcnow()


def test_non_accessible_organisation(client):
    fake_auth = client.post('/auth/register', json={
        'userId': '300',
        'firstName': 'Not John',
        'lastName': 'Cena',
        'email': 'Not.Tohn.Cena@example.com',
        'password': 'password',
        'phone': '1234567890'
    })

    test_auth = client.post('/auth/register', json={
        'userId': '400',
        'firstName': 'John',
        'lastName': 'Cena',
        'email': 'Tohn.Cena@example.com',
        'password': 'password',
        'phone': '1234567890'
    })
    inf = test_auth.get_json()
    users_access_token = inf['data']['accessToken']
    headers = {'Authorization': f'Bearer {users_access_token}'}
    
    response = client.get(f'/api/organisations/{1}', headers=headers)
    assert response.status_code == 401
    data = json.loads(response.data)
    assert data['message'] == "You do not have access to this organisation"



# End to End Testing

def test_successful_registration(client):
    response = client.post('/auth/register', json={
        'userId': '999',
        'firstName': 'Onifade',
        'lastName': 'Racheal',
        'email': 'Onifade.Racheal@example.com',
        'password': 'password',
        'phone': '1234567890'
    })

    data = json.loads(response.data)
    assert response.status_code == 201
    assert data['status'] == 'success'
    assert data['data']['user']['firstName'] == "Onifade"
    assert data['data']['user']['lastName'] == "Racheal"
    assert data['data']['user']['email'] == "Onifade.Racheal@example.com"
    assert 'accessToken' in data['data']

    with client.application.app_context():
        user = User.query.filter_by(email="Onifade.Racheal@example.com").first()
        assert user is not None
        assert user.organisation[0].name == "Onifade's Organisation"



def test_successfull_login(client):
    client.post('/auth/register', json={
        "userId": '999',
        "firstName": "Onifade",
        "lastName": "Racheal",
        "email": "Onifade.Racheal@example.com",
        "password": "password",
        "phone": "1234567890"
    })
    response = client.post('/auth/login', json={
        "email": "Onifade.Racheal@example.com",
        "password": "password"
    })
    data = json.loads(response.data)
    assert response.status_code == 200
    assert data['status'] == 'success'
    assert data['data']['user']['email'] == "Onifade.Racheal@example.com"
    assert 'accessToken' in data['data']

# FIELD TESTS
def test_for_missing_firstName(client):
    response = client.post('/auth/register', json={
        "userId": '999',
        "firstName": "",
        "lastName": "Racheal",
        "email": "Onifade.Racheal@example.com",
        "password": "password",
        "phone": "1234567890"
    })

    data = json.loads(response.data)
    assert response.status_code == 422
    print (data)
    assert data['errors'][0]['message'] == 'firstName should not be empty'


def test_for_missing_lastName(client):
    response = client.post('/auth/register', json={
        "userId": '999',
        "firstName": "Onifade",
        "lastName": "",
        "email": "Onifade.Racheal@example.com",
        "password": "password",
        "phone": "1234567890"
    })

    data = json.loads(response.data)
    assert response.status_code == 422
    assert data['errors'][0]['message'] == 'lastName should not be empty'


def test_duplicate_email(client):
    client.post('/auth/register', json={
        "userId": '999',
        "firstName": "Test",
        "lastName": "User",
        "email": "Onifade.Racheal@example.com",
        "password": "password",
        "phone": "1234567890"
    })

    response = client.post('/auth/register', json={
        "userId": '1000',
        "firstName": "Onifade",
        "lastName": "Racheal",
        "email": "Onifade.Racheal@example.com",
        "password": "password",
        "phone": "1234567890"
    })

    data = json.loads(response.data)
    assert response.status_code == 422
    assert data['errors'][0]['message'] == "email already exists"
