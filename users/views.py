from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authentication import get_authorization_header, SessionAuthentication, TokenAuthentication
from rest_framework.authtoken.models import Token
from .serializers import UserSerializer
from .models import User
import jwt, datetime

# AUTH CHECK
from rest_framework.decorators import authentication_classes,permission_classes
from rest_framework.permissions import IsAuthenticated

# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user = User.objects.get(email=request.data['email'])
        token = Token.objects.create(user=user)
        return Response({"token": token.key, "user": serializer.data})


class LoginView(APIView):
    def post(self, request):
        user = User.objects.filter(email=request.data['email']).first()

        if user is None:
            raise AuthenticationFailed('User not found')

        if not user.check_password(request.data['password']):
            raise AuthenticationFailed('Incorrect password')


        token, created = Token.objects.get_or_create(user=user)

        serializer = UserSerializer(instance=user)

        response = Response()

        response.set_cookie(key='userToken', value=token.key, httponly=True)
        response.data = {
            "message": "success",
            "token": token.key,
            "user": serializer.data
        }

        return response




class UserView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        return Response({
            "message": "success",
            "id": request.user.id,
            "name": request.user.name
        })

        




class LogoutView(APIView):
    def post(self, _):
        response = Response()
        response.delete_cookie('jwtToken')

        response.data = {
            "message": "success"
        }
        return response