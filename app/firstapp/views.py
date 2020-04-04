# Create your views here.
#IMPORT models
from .models import Movie,ApiUsers

#IMPORT LIBRARIRES/FUNCTIONS
#from django.shortcuts import render , HttpResponse
from django.http import JsonResponse
import json
from firstapp.customClasses import *
#IMPORT DJANGO PASSWORD HASH GENERATOR AND COMPARE
from django.contrib.auth.hashers import make_password, check_password

#check_password(noHashPassword,HashedPassword) this funcion validate if the password match to the hash

def login(request):

    #VALIDATE METHOD
    response_data={}
    if request.method == 'POST':
        #CHECK JSON STRUCTURE
        #DECLARE RESPONSE
        if checkJson().isJson(request.body)==True:
            datitosj = json.loads(request.body) #Leer json
            errorsito = ""

        #CHECK JSON CONTENT


        #CHECK IF USER EXITST
            if 'user' not in datitosj:
                errorsito = "NO hay usuario"
        #TAKE PASSWORD OF THE USER
            elif 'password' not in datitosj:
                errorsito="password missing"
            else:
                try:
                    usersql = ApiUsers.objects.get(user = datitosj['user'])
                except Exception as e:
                    response_data['result'] = 'error'
                    response_data['message'] = 'User incorrect'
                    return JsonResponse(response_data, status=401) #Error Json
                psw  = datitosj['password'] #COntraseña que se envia
                Hachiko = usersql.password


        #CHECK IF PASSWORD IS CORRECT
                if (check_password(psw, Hachiko) == False):
                    errorsito = "User or password incorrect"
            
                elif (usersql.api_key == None):
                    apigenerada = ApiKey().generate_key_complex()
                    usersql.api_key = apigenerada
                    usersql.save() #Inserta los datos en la base de datos
                    
                

            if (errorsito != ""):
                response_data['result'] = 'error'
                response_data['message'] = errorsito
                return JsonResponse(response_data, status=402)

            else:
                response_data['result'] = 'EXITO'
                response_data['message'] = 'Valido'
                response_data['ApiKey'] = usersql.api_key
                return JsonResponse(response_data, status=200)
        else:
            response_data['result'] = 'error'
            response_data['message'] = 'Esta mal el JSON'
        return JsonResponse(response_data, status = 100)

    
    else:
        response_data['result'] = 'error'
        response_data['message'] = 'NO es post'
        return JsonResponse(response_data, status = 402)
        #CHECK IF USER HAS API-KEY
        #obj.api_key = newApiKey
        #obj.save()


        #RETURN RESPONSE

def movies(request):

    #VALIDATE METHOD
    response_data={}
    response_data['movies'] = {}
    if request.method == 'POST':
        #CHECK JSON STRUCTURE
        #DECLARE RESPONSE
        if checkJson().isJson(request.body)==True:
            datitosj = json.loads(request.body) #Leer json
            errorsito = ""

        #CHECK JSON CONTENT


            try:
                usersql = ApiUsers.objects.get(user = datitosj['user'])
            except Exception as e:
                response_data['result'] = 'error'
                response_data['message'] = 'User incorrect'
                return JsonResponse(response_data, status=401) #Error Json
            psw  = datitosj['password'] #COntraseña que se envia
            Hachiko = usersql.password


        #CHECK IF PASSWORD IS CORRECT
            if (check_password(psw, Hachiko) == False):
                errorsito = "User or password incorrect"   
                

            if (errorsito != ""):
                response_data['result'] = 'error'
                response_data['message'] = errorsito
                return JsonResponse(response_data, status=402)

            if ApiKey().check(request):
                if request.headers["user-api-key"] == usersql.api_key:
                    j = 0
                    for i in Movie.objects.all():
                        response_data['movies'][j] = {}
                        response_data['movies'][j]['id'] = i.movieid
                        response_data['movies'][j]['title'] = i.movietitle
                        response_data['movies'][j]['releaseDate'] = i.releasedate
                        response_data['movies'][j]['imageUrl'] = i.imageurl
                        response_data['movies'][j]['description'] = i.description
                        j = j + 1
                    response_data['result'] = 'success'
                    return JsonResponse(response_data, status=200)

                else:
                    response_data['result'] = 'ERROR'
                    response_data['message'] = 'Api Key Invalido'
                    return JsonResponse(response_data, status=401)

            else:
                response_data['result'] = 'EXITO'
                response_data['message'] = 'Valido'
                response_data['ApiKey'] = usersql.api_key
                return JsonResponse(response_data, status=200)
        else:
            response_data['result'] = 'error'
            response_data['message'] = 'Esta mal el JSON'
        return JsonResponse(response_data, status = 100)

    
    else:
        response_data['result'] = 'error'
        response_data['message'] = 'NO es post'
        return JsonResponse(response_data, status = 402)
        #CHECK IF USER HAS API-KEY
        #obj.api_key = newApiKey
        #obj.save()


        #RETURN RESPONSE


def makepassword(request,password):
    hashPassword = make_password(password)
    response_data = {}
    response_data['password'] = hashPassword
    return JsonResponse(response_data, status=200)
