<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Validator;
use Illuminate\Support\Arr;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(),[
            'name' => 'required|string', 
            'email' => 'required|email|unique:users',
            'password' => 'required'
        ], $messages = ['email.unique' => __('Email already exists')]);

        if($validator->fails()){
            return response()->json([
                "message" => Arr::first(Arr::flatten($validator->messages()->get('*')))
            ],400);
        }

        try {
            DB::beginTransaction();
            $user = new User();
            $user->name = $request->name;
            $user->email = $request->email;
            $user->password = Hash::make($request->password);
            $user->is_coach = true;
            $user->save();
            DB::commit();
            return response()->json(["user" => $user]);
        } catch (Exception $error) {
            DB::rollback();
            return response()->json([
                "message" => $error->getMessage()
            ], 500);
        }
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), 
        [
            'email' => 'required|email|exists:users',
            'password' => 'required'
        ],$messages = ['email.exists' => __('Email does not exist for any account!')]);

        if($validator->fails()){
            return response()->json(['message' => Arr::first(Arr::flatten($validator->messages()->get('*')))]);
        }

        $user = User::where('email', $request->email)->first();
        if($user){
            Auth::attempt(['email' => $request->email, 'password' => $request->password]);
            $token = $user->createToken($user->name)->plainTextToken;
            return response()->json(['token' => $token, 'message' => 'Login Successful!', 'data' => ['user' => $user]]);
        } else {
            return response()->json([
                "message" => __("Invalid credentials. Please check your password and try again")
            ], 401);
        }
    }

    public function logout(Request $request){
        $user = \Auth::user();
        if(!empty($user)){
            $request->user()->currentAccessToken()->delete();
            return response()->json([
                "message" => __("Logout successful")
            ]);
        }else {
            return response()->json(["message" => __("Logout Failed!")], 401);
        }
    }

    public function profile(Request $request){
        $user = User::find(Auth::id());
        return response()->json(['status' => true, 'message' => 'Profile Retrieved!', 'data' => ['user' => $user]]);
    }
}
