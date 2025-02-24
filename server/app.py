#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')
        
        try:
            user = User(username=username, image_url=image_url, bio=bio)
            user.password_hash = password
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(), 201
        except IntegrityError as error:
            if 'UNIQUE' in str(error):
                return {'error': 'username must be unique'}, 422
            else:
                return {'error': 'username must exist'}, 422
            
        

class CheckSession(Resource):
    def get(self):
        self.user_id = session.get("user_id")
        if self.user_id:
            user = User.query.filter_by(id=self.user_id).first()
            return user.to_dict(), 200
        else:
            return {'error': 'Not logged in'}, 401

class Login(Resource):
    def post(self):
        user = User.query.filter(
            User.username == request.get_json()['username']
        ).first()
        
        if user:
            session['user_id'] = user.id
            return user.to_dict()
        return {'error': 'username or password are incorrect'}, 401

class Logout(Resource):
    def delete(self):
        self.user_id = session.get("user_id")
        if self.user_id:
            session.clear()
            return {}, 204
        else:
            return {'error': 'not logged in '}, 401

class RecipeIndex(Resource):
    def get(self):
        self.user_id = session.get("user_id")
        if self.user_id:
            response_dict_list = [
                {
                    'title': recipe.title,
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': recipe.user.to_dict()
                }
                for recipe in Recipe.query.filter_by(user_id=self.user_id).all()
            ]
            return response_dict_list, 200
        else:
            return {'error': 'Not logged in'}, 401
        
    def post(self):
        self.user_id = session.get("user_id")
        if not self.user_id:
            return {'error': 'Not logged in'}, 401
        
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')
        
        if not title or not instructions or not minutes_to_complete:
            return {'error': 'Invalid data'}, 422
        
        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=self.user_id
            )
            db.session.add(recipe)
            db.session.commit()
            return {
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': recipe.user.to_dict()
            }, 201
        except Exception as e:
            return {'error': str(e)}, 422

            


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)