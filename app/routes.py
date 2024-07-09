from flask import Blueprint, request, jsonify
from app import bcrypt, db
from app.database import User, Organisation
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import datetime
from email_validator import validate_email, EmailNotValidError
import uuid

auth = Blueprint('auth', __name__)
api = Blueprint('api', __name__)

@auth.route('/')
def index():
    return jsonify({"status": "success", "message": "API is running"}), 200

@auth.route('/auth/register', methods=['POST'])
def register():

    if request.content_type != 'application/json':

       return jsonify({"errors": [
    {
        "field": "email",
        "message": "Email is required"
    },
    {
        "field": "password",
        "message": "Password is required"
    },
    {
        "field": "firstName",
        "message": "FirstName is required"
    },
    {
        "field": "lastName",
        "message": "LastName is required"
    }
]}), 422

    data = request.get_json()
    firstName = data['firstName']
    lastName = data['lastName']
    email = data['email']
    password = data['password']
    phone = data['phone']


    if len(data) == 0:
       return jsonify({"errors": [
    {
        "field": "email",
        "message": "Email is required"
    },
    {
        "field": "password",
        "message": "Password is required"
    },
    {
        "field": "firstName",
        "message": "FirstName is required"
    },
    {
        "field": "lastName",
        "message": "LastName is required"
    }
]}), 422
    
    try:

       
            
        if request.method == 'POST':
            required_fields = ['firstName', 'lastName', 'email']
            errors = []
            if password:
                hashed_pwd = bcrypt.generate_password_hash(password, 10).decode('utf-8')
            else:
                errors.append({"field": "password", "message":  "password should not be empty"})

            try:
                valid_email = validate_email(email).email
            except EmailNotValidError as e:
                errors.append({"field": "email", "message": str(e)})
                
            if 'email' in data and User.query.filter_by(email=email).first():
                errors.append({"field": "email", "message": "email already exists"})
            
            for field in required_fields:
                if field not in data or not data[field]:
                    errors.append({"field": field, "message": field + " should not be empty"})
            
           
            
            if errors:
                return jsonify({"errors": errors}), 422
            
            default_organisation_name = f"{firstName}'s Organisation"
            user = User( firstName=firstName, lastName=lastName, email=email, password=hashed_pwd, phone=phone)
            org = Organisation(name=default_organisation_name)
            db.session.add(user)
            db.session.add(org)
            user.organisation.append(org)
            db.session.commit()
            
            access_token = create_access_token(identity={'userId': user.id})
            success = {
                "status": "success",
                "message": "Registration successful",
                "data": {
                    "accessToken": access_token,
                    "user": {
                        "userId": user.id,
                        "firstName": user.firstName,
                        "lastName": user.lastName,
                        "email": user.email,
                        "phone": user.phone
                    }
                }
            }
            return jsonify(success), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "Bad request", "message": "Registration unsuccessful", "statusCode: 400}), 400

    except IntegrityError:
        db.session.rollback()
        return jsonify({"status": "Bad request", "message": "Registration unsuccessful", "statusCode": 400}), 400


    


@auth.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity={'userId': user.id})
        success = {
            "status": "success",
            "message": "Login successful",
            "data": {
                "accessToken": access_token,
                "user": {
                    "userId": user.id,
                    "firstName": user.firstName,
                    "lastName": user.lastName,
                    "email": user.email,
                    "phone": user.phone
                }
            }
        }
        return jsonify(success), 200
    else:
        return jsonify({"status": "Bad request", "message": "Login unsuccessful", "statusCode": 400}), 400

@api.route('/api/users/<string:user_id>', methods=['GET'])
@jwt_required()
def users(user_id):
    user = User.query.get_or_404(user_id)
    current_user = get_jwt_identity()

    for orgs in User.query.filter_by(id=current_user['userId']).first().organisation:
        if orgs in user.organisation:
            user_detail = {
                "status": "success",
                "message": "User gotten successfully",
                "data": {
                    "userId": user.id,
                    "firstName": user.firstName,
                    "lastName": user.lastName,
                    "email": user.email,
                    "phone": user.phone
                }
            }
            return jsonify(user_detail), 200
    return jsonify({'message': 'Unauthorized access'}), 401

@api.route('/api/organisations', methods=['GET'])
@jwt_required()
def organisations_list():
    current_user = get_jwt_identity()
    organisation_list = []
    user = User.query.get(current_user['userId']).organisation

    for orgs in user:
        organisation_list.append({
            "orgId": str(orgs.id),
            "name": orgs.name,
            "description": orgs.description
        })

    user_organisations = {
        "status": "success",
        "message": "Organisations gotten successfully",
        "data": {
            "organisations": organisation_list
        }
    }
    return jsonify(user_organisations), 200

@api.route('/api/organisations/<string:orgId>', methods=['GET'])
@jwt_required()
def all_organisations(orgId):
    org = Organisation.query.filter_by(id=orgId).first()
    current_user = get_jwt_identity()
    user_orgs = User.query.filter_by(id=current_user['userId']).first().organisation

    if org not in Organisation.query.all():
        return jsonify({"status": "error", "message": "Organization doesn't exist"}), 404

    if org in user_orgs:
        organisation = {
            "status": "success",
            "message": "Organisation gotten successfully",
            "data": {
                "orgId": org.id,
                "name": org.name,
                "description": org.description
            }
        }
        return jsonify(organisation), 200
    else:
        return jsonify({"status": "error", "message": "You do not have access to this organisation"}), 401

@api.route('/api/organisations', methods=['POST'])
@jwt_required()
def create_organisation():
    data = request.get_json()
    name = data['name']
    description = data['description']

    if request.method == 'POST':
        required_fields = ['name']
        errors = []
        for field in required_fields:
            if field not in data or not data[field]:
                errors.append({"field": field, "message": field + " should not be empty"})
        
        if errors:
            return jsonify({"errors": errors}), 422

        current_user = get_jwt_identity()
        user = User.query.get(current_user['userId'])
        org = Organisation(name=name, description=description)
        user.organisation.append(org)
        db.session.commit()

        response = {
            "status": "success",
            "message": "Organisation created successfully",
            "data": {
                "orgId": org.id,
                "name": org.name,
                "description": org.description
            }
        }
        return jsonify(response), 201

@api.route('/api/organisations/<string:orgId>/users', methods=['POST'])
def add_to_org(orgId):
    data = request.get_json()
    userId = data['userId']
    user = User.query.get(userId)
    org = Organisation.query.filter_by(id=orgId).first()
    
    if user is None:
        return jsonify({"status": "error", "message": "User does not exist"}), 404
    
    if org is None:
        return jsonify({"status": "error", "message": "Organisation does not exist"}), 404

    user.organisation.append(org)
    db.session.commit()
    
    return jsonify({"status": "success", "message": "User added to organisation successfully"}), 200
