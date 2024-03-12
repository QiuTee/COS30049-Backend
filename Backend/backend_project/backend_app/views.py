from rest_framework.decorators import APIView
from rest_framework.response import Response 
from rest_framework.generics import GenericAPIView
from backend_app.serializer import *
from .emails import *
from rest_framework_simplejwt.tokens import RefreshToken
from email import *
from django.core.exceptions import ObjectDoesNotExist
from .keyofuser import *
from rest_framework_simplejwt.tokens import AccessToken
from ecdsa import SigningKey, SECP256k1
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.hashers import check_password
from .keyofuser import *
import bcrypt
from .functions import *
from .connect_w3 import connect_to_w3
from decimal import Decimal
from decouple import config
from .pending import get_pending_transactions
# from .history import process_tx_list
# from .transaction import process_transaction
from .process import process_transaction
from django.http import HttpResponse
class LoginAPI(GenericAPIView):
    def post(self, request):
        w3 = connect_to_w3()
        serializer = LoginSerializer(data=request.data)
        try :
            if serializer.is_valid(raise_exception=True):
                username = serializer.validated_data['username']
                password = serializer.validated_data['password']

                user = User.objects.get(username=username)

                if check_password(password, user.password):
                    refresh = RefreshToken.for_user(user)
                    refresh['username'] = user.username
                    wallet = w3.to_checksum_address(user.user_address)
                    balance = w3.from_wei(w3.eth.get_balance(wallet), "ether")
                    return Response({
                        'status': '200 OK',
                        'data': {
                            'id': user.id,
                            'username': user.username,
                            'email': user.email,
                            'lastname': user.last_name,
                            'name': user.first_name + " " + user.last_name,
                            'balance': balance,
                            'phone': user.phoneNumber,
                            'address': user.user_address,
                            'refresh': str(refresh),
                            'token': str(refresh.access_token)
                        },
                        'message': 'Login successful'
                    })
                else :
                    return Response({
                            'message' :'You have enter an invalid username or password',
                            'status' : '401 Unauthorized'
                            })
        except Exception as e :
            return Response({
                            'message' :'You have enter an invalid username or password',
                            'status' : '401 Unauthorized'
                            })


class RegisterAPI(GenericAPIView):
    def post(self, request) :
        password = request.data.get('password')
        retypePassword = request.data.get('retypePassword')
        if not password == retypePassword :
            return Response({
                'status' : '401 Unauthorized' ,
                'message' : 'Password and retype password is not match'

            })
        serializers = UserInfoSerializer(data = request.data )
        try :
            if serializers.is_valid(raise_exception= True) :
                user = serializers.save()
                send_otp_via_email(serializers.data['email'])
                return Response({
                'status' : '200 OK',
                'data' :
                    {
                    'id' : user.id,
                    'username' : user.username,
                    'email' : user.email,
                    'lastname' : user.last_name,
                    'name' : user.first_name + " " + user.last_name,
                    'phone' : user.phoneNumber ,
                    'message' :  'Please do not skip the last step to verify your account.'
                    }
                })
        except Exception as e:
            return Response(
                {'status' : '401 Unauthorized' ,
                 'error' : 'SignUp Error ',
                 'message' :'Please enter all fields'
                })

class VerifyOTP(APIView):
    def post(self, request):
        w3 = connect_to_w3()
        code = request.data.get('otp')

        try:
            serializers = OneTimePassword.objects.get(code=code)
            user_email = User.objects.get(otp=code)

            if not user_email.otp == code:
                user_email.is_verified = False
                return Response({'status': '400', 'message': 'OTP is no longer valid', 'data': 'otp wrong'})

            user = serializers.user
            if serializers.check_run_time():
                send_otp_via_email(user_email)
                return Response({'status': '400', 'message': 'OTP is no longer valid', 'data': 'otp wrong'})

            if not user_email.is_verified:
                user_email.is_verified = True



                pin = str(randint(1000000, 9999999))
                print(pin)
                hash_pin = bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt())
                user.pin = hash_pin
                print(f"Hash pin : {user.pin}")
                user_email.save()

                subject = "Your pin code: "
                email_body = f"""
                Hi {user.first_name},

                Thank you for using Digicode ! We have generated a new pin code for your recent transaction. Please ensure the confidentiality of this pin code and do not share it with anyone.

                IMPORTANT: Your transaction pin code is: {pin}
                """
                from_email = settings.EMAIL_HOST
                d_mail = EmailMessage(subject=subject, body=email_body, from_email=from_email, to=[user.email])
                d_mail.send(fail_silently=True)


                create_account , address = create_user(w3)
                user.user_address = address
                user.save()
                data = encrypt_private_key(create_account , user.pin)
                user.data = data
                user.save()

                decrypt = decrypt_private_key(w3, user.data, user.pin)
                print(decrypt.hex)
                return Response({'status': '200 OK', 'message': 'Account verified successfully',
                                 'data': f'Please check and remember your pin is being send to your email'})
            return Response({'status': '400', 'message': 'Code is invalid', 'data': 'otp wrong'})
        except ObjectDoesNotExist:
            return Response({'status': '400', 'message': 'OTP is invalid', 'data': 'otp wrong'})

class updateProfile(APIView) :
    permissions = [IsAuthenticated]
    def put(self, request) :
        token = request.data.get('token')
        access_token = AccessToken(token)
        username_from_token = access_token['username']
        email =request.data.get('email')
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')
        phone = request.data.get('phone')
        try :
            user = User.objects.get(username = username_from_token )
            if(user.email != email) :
                user.email = email
            if(user.phoneNumber != phone) :
                user.phoneNumber = phone
            if not check_password(password, user.password):
                if(password == confirm_password) :
                    user.set_password(password)

            else:
                return Response({
                    'status': '401 Unauthorized ',
                    'message': 'Confirm password or password is not match'
                })

            user.save()
            return Response({
                    'status': '200 OK',
                    'message': 'Change successfully'
                })
        except Exception as e :
            return Response({
                    'status': '401 Unauthorized',
                    'message': 'Password change successfully '
            })




class ForgetPassword(APIView):
    def post(self, request) :
        username = request.data.get('username')

        if not User.objects.filter(username=username).exists() :
            return Response({
                    'status': '401 Unauthorized ',
                    'message': 'Username does not exist'
                })
        user = User.objects.get(username=username)
        save_mail = SaveEmailModel(email = user.email)
        save_mail.save()
        send_otp_via_email_for_reset(user.email)

        first_data = SaveEmailModel.objects.first()
        print(first_data)
        return Response({
                    'status': '200 OK',
                    'message': 'OTP sent successfully'
                })

class ResetPassword(APIView) :
    def put(self , request) :
        first_data = SaveEmailModel.objects.first()
        user = User.objects.get(email=first_data)
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')
        otp = request.data.get('otp')
        print(f"Password: {password}")
        print(f"Confirm Password: {confirm_password}")
        if not first_data.check_run_time() :
            if otp == first_data.code :
                if  confirm_password == password :
                    user.set_password(password)
                    user.save()
                    SaveEmailModel.objects.all().delete()
                    return Response({
                        'status': '200 OK',
                        'message': 'Change password successfully'
                    })
                return Response({
                            'status': '401 Unauthorized ',
                            'message': 'Password not match'
                        })
            return Response({
                            'status': '401 Unauthorized ',
                            'message': 'Password not match'
                        })
        else :
                send_otp_via_email_for_reset(first_data.email)
                return Response({'status' : '401' ,'message' : 'OTP is no longer valid' , 'data' : 'otp wrong' })



class TestPin(APIView):
    def post(self, request):
        email = request.data.get('email')
        print(email)
        pin = request.data.get('pin')
        print(pin)
        data = User.objects.get(email = email)
        if bcrypt.checkpw(pin.encode('utf-8'), data.pin):
            print(True)
        else :
            print(False)
        print(f"{data.pin}")
        return Response({'status': 200})


class TransactionView(APIView):
    def post(self, request):
        try:
            w3 = connect_to_w3()
            token = request.data.get('token')
            to_address = request.data.get('to_address')
            amount = request.data.get('amount')
            pin = request.data.get('pin')
            access_token = AccessToken(token)
            username_from_token = access_token['username']
            data = User.objects.get(username=username_from_token)

            if not w3.is_address(to_address):
                return Response({
                    'status': '400 Bad Request',
                    'message': 'Invalid to_address'
                })

            receiver = w3.to_checksum_address(to_address)

            if not bcrypt.checkpw(pin.encode('utf-8'), data.pin):
                return Response({
                    'status': '401 Unauthorized',
                    'message': 'Invalid PIN'
                })

            contract_address = read_contract_address()
            abi, abi2 = open_transaction_factory()
            contract_instance = w3.eth.contract(address=contract_address, abi=abi)
            private_key = decrypt_private_key(w3, data.data, data.pin)
            amount_in_wei = w3.to_wei(amount, 'ether')
            transaction = transaction_json(w3, data.user_address, amount_in_wei)

            if check_fee(w3, data.user_address, amount_in_wei):
                return Response({
                    'status': '400',
                    'message': 'Not enough fee to transaction'
                })

            receipt, success = createTransaction(w3, contract_instance, receiver, private_key, amount_in_wei, transaction)
            hash_block = receipt.blockHash.hex()
            transaction_hash = receipt.transactionHash.hex()

            if success:
                balance = w3.from_wei(w3.eth.get_balance(data.user_address), "ether")
                transaction_address = get_last_transaction(contract_instance)
                history = HistoryModel(user_address=data.user_address, username=data.username, hash_block=hash_block,
                                    contract_address=transaction_address, transaction_hash=transaction_hash)
                history.save()
                return Response({
                    'status': '200 OK',
                    'message': 'Transaction was made successfully',
                    'data': {'balance': balance}
                })
            else:
                return Response({
                    'status': '400',
                    'message': receipt
                })
        except Exception as e:
            return Response({
                'status': '500 Internal Server Error',
                'message': str(e)
            })
        


class PendingView(APIView) :
    def post(self , request) :
        w3 = connect_to_w3()
        token = request.data.get('token')
        access_token = AccessToken(token)
        username_from_token = access_token['username']
        user_address = User.objects.get(username=username_from_token)
        user_add = user_address.user_address
        history = get_pending_transactions(w3, user_add)
        return Response({
            'status': '200 OK',
            'message': 'Successfully retrieved pending transactions',
            'data' : history
            })
    

class HistoryView(APIView) : 
    def post(self, request):
        w3 = connect_to_w3()
        token = request.data.get('token')
        access_token = AccessToken(token)
        username_from_token = access_token['username']
        user = User.objects.get(username=username_from_token)

        actions = ['txlist', 'txlistinternal']  # Danh sách các action

        history = []
        id = 0
        for action in actions:
            params = {
                'module': 'account',
                'action': action,
                'address': user.user_address,
                'startblock': 0,
                'endblock': 99999999,
                "page": 1,
                "offset": 10,
                'sort': 'asc',
                'apikey': config('API_KEY')
            }

            offset = 0
            while True:
                params['offset'] = 10  # Set the offset
                params['page'] = offset + 1  # Set the page number

                data_result = get_data_api(params)
                if not data_result:
                    break  # If the result is empty, break the loop

                for each_result in data_result:
                    id += 1 
                    time = convert_to_time(int(each_result['timeStamp']))
                    amount_wei = int(each_result['value'])
                    amount_eth = w3.from_wei(amount_wei, "ether")
                    amount_eth = Decimal(amount_eth)
                    amount_decimal = "{:.50f}".format(amount_eth).rstrip('0')
                    if user.user_address == w3.to_checksum_address(each_result['to']):
                        amount = f"+{amount_decimal}"
                    else:
                        amount = f"-{amount_decimal}"
                    if each_result['isError'] == "0":
                        valid = True
                    else:
                        valid = False
                    item = {
                        "id" : id , 
                        "timestamp": time,
                        "amount": amount,
                        "valid": valid,
                        "from" : each_result['from'] ,
                        "to": each_result['to']
                    }
                    print(item)
                    history.append(item)

                offset += 1

        return Response({
            'status': '200 OK',
            'message': 'Successfully retrieved history',
            'data': history 
        })   
          

class ExecuteView(APIView):
    def post(self, request):
        w3 = connect_to_w3()
        token = request.data.get('token')
        access_token = AccessToken(token)
        username_from_token = access_token['username']
        print(username_from_token)
        pin = request.data.get('pin')
        print(pin)
        transaction_address = request.data.get('item')
        action = request.data.get('action')
        user = User.objects.get(username=username_from_token)
        user_address = user.user_address
        abi, abi2 = open_transaction_factory()
        private_key = decrypt_private_key(w3, user.data, user.pin)
        send_transaction = transaction_json(w3, user.user_address, 0)

        history = []
        if bcrypt.checkpw(pin.encode('utf-8'), user.pin):
            history, balance = process_transaction(action, user, transaction_address, w3, abi2, private_key, send_transaction ,user_address)

            return Response({
                'status': '200 OK',
                'message': 'Successfully retrieved pending transactions',
                'data': {
                    'history': history,
                    'balance': balance
                }
            })


class AllBlockView(APIView):
    def get(self , request) :
        w3 = connect_to_w3()
        block_chain = []
        unique_block = []
        return_block = []

        blocks = HistoryModel.objects.all()
        for bl in blocks :
            if bl is not None :
                block_chain.append(bl.hash_block) 
                block_chain.append(bl.hash_block_transaction)
            


        for unique in block_chain :
            if unique not in unique_block :
                # print(unique)
                unique_block.append(unique)
        
        for block in unique_block : 
            block = w3.eth.get_block(block, True)
            block_item = {
                'number' : block.number,
                'hash' : block.hash.hex() ,
                'previous_hash' : block.parentHash.hex() ,
                'nonce' : int(block.nonce.hex(), 16) ,
                'timestamp' : block.timestamp
            }
            return_block.append(block_item)
            print(return_block)
        return Response({
                'status': '200 OK',
                'message': 'Fetch all blocks successfully ', 
                'data' : return_block
            })

class BlockDetailView(APIView):
    def get(self, request, block_id):
        w3 = connect_to_w3()
        print(block_id)

        transactions_hash = []
        return_transactions = []
        blocks = HistoryModel.objects.all()
        print(blocks)
        id = 0 
        # if w3.is_address(block_id):
        
        fetch_block =  w3.eth.get_block(block_id, True)
        all_transaction = fetch_block.transactions
        for db_trans in blocks : 
            transactions_hash.append(db_trans.transaction_hash)
            transactions_hash.append(db_trans.execute_transaction_hash)
            print(db_trans)
        for trans in all_transaction : 
            if trans.hash.hex()  in transactions_hash : 
                id += 1 
                print(trans.hash.hex())
                return_transactions.append({
                        'id' : id ,
                        'from' : trans['from'] ,
                        'to' : trans['to'] , 
                        'hash' : trans.hash.hex() , 
                        'value' : (w3.from_wei(trans.value, 'ether'))  
                        })
                
        return Response({
            'status': '200 OK',
            'message': 'Block detail fetched successfully',
            'data': return_transactions
        })