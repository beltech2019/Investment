<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Foundation\Auth\ResetsPasswords;
use App\Models\PasswordReset;
use Carbon\Carbon;
use App\Notifications\PasswordResetRequest;
use App\Notifications\PasswordResetSuccess;
use App\Mail\SendForgotPassword;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Validator;
use Illuminate\Support\Facades\Input;
use Log;
use Mail;
use Exception;
use DB;

class ResetPasswordController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Password Reset Controller
    |--------------------------------------------------------------------------
    |
    | This controller is responsible for handling password reset requests
    | and uses a simple trait to include this behavior. You're free to
    | explore this trait and override any methods you wish to tweak.
    |
    */

    use ResetsPasswords;

    /**
     * Where to redirect users after resetting their password.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest');
    }
	
	public function postForgotPassword(Request $request)
    {

		$validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'user_type' => 'required',
        ]);
		
        if ($validator->fails()) {
			$error = $validator->errors()->all();
			return response()->json(['success'=>false,'validator'=>true, 'error' => $error],config("serverConstant.STATUS_BAD_REQUEST"));	
		}
		try{
			$user = User::where('username',$request->email)->where('user_type',$request->user_type)->whereNull('deleted_at')->where('status',config('serverConstant.USER_ACTIVE_STATUS'))->first();
			if (!$user)
			{
				throw new Exception(config("exception.INVALID_EMAIL_ID"));
			}
				$passwordReset = PasswordReset::updateOrCreate(
				['email' => $user->username],
				[
					'email' => $user->username,
					'userType' => $user->user_type,
					'token' => str_random(config('serverConstant.FORGORT_TOKEN_STRING_LENGTH'))
				]
			);
			if ($user && $passwordReset)
			{
				//$response = $user->notify(new PasswordResetRequest(['token' => $passwordReset->token,'userType' => $user->user_type]));
				$url = url('/password/change/'.$passwordReset->token.'/'.$user->user_type);
				Mail::to($user->username)->send(new SendForgotPassword($url));
			}
        }
        catch (\Exception $e) {
            return response()->json(['success'=>false, 'validator'=>false,'error' => $e->getMessage()],config("serverConstant.STATUS_BAD_REQUEST"));
        } 
		return response()->json(['success'=>true, 'response' => '',],config("serverConstant.STATUS_OK"));
    }
	
	
    public function changePassword(Request $request)
    {
		$validator = Validator::make($request->all(), [
            'username' => 'required|email',
            'password' => 'min:6|required_with:confirm_password|same:confirm_password',
            'user_type' => 'required',
            'token' => 'required',
            'id' => 'required',
			'confirm_password' => 'min:6'
        ]);
        if ($validator->fails()) {
			 return back()->withInput(Input::all())->withErrors($validator)->withInput();;
        }
		try {
			$resetPasswordInfo = [
				'email'=>$request->username,
				'password'=>$request->password,
				'userType'=>$request->user_type,
				'token'=>$request->token,
				'id'=>$request->id,
			];
			$forgotRes = $this->postCURLWithAuth('api/resetPassword',$resetPasswordInfo );
			if($forgotRes && $forgotRes->content && $forgotRes->content->success)
			{
				$passwordReset = $forgotRes->content->response;
				
			}
			else{				
				$exceptionVal = $this->getErrorMessage($forgotRes);
				throw new Exception($exceptionVal);
			}
			return redirect('/');
		} catch (\Exception $e) {
			$msg = $e->getMessage();
			Log::error('Exception: '.$msg);
			return view('pages.changePassword',['passwordReset' => ''])->withErrors(["invalid_user" => $msg]);
		}
    }
	
	
	public function findUser($token,$userType)
    {
		try {

			$forgotRes = $this->postCURLWithAuth('api/findUserByToken/'.$token.'/'.$userType,'');
			if($forgotRes && $forgotRes->content && $forgotRes->content->success)
			{
				$passwordReset = $forgotRes->content->response;
				
			}
			else{				
				$exceptionVal = $this->getErrorMessage($forgotRes);
				throw new Exception($exceptionVal);
			}
			return view('pages.changePassword', ['passwordReset' => $passwordReset]);
		} catch (\Exception $e) {
			$msg = $e->getMessage();
			Log::error('Exception: '.$msg);
			return view('pages.changePassword',['passwordReset' => ''])->withErrors(["invalid_user" => $msg]);
		}
    }
	
	
	public function findUserByToken($token,$userType)
    {
		try {
        $passwordReset = PasswordReset::where('token', $token)->where('userType',$userType)->first();
        if (!$passwordReset)
             throw new \Exception(config('exception.THIS_PASSWORD_RESET_TOKEN_IS_INVALID'));
        if (Carbon::parse($passwordReset->updated_at)->addMinutes(config('serverConstant.TOKEN_EXPIRY_TIME'))->isPast()) {
            $passwordReset->delete();
            throw new \Exception(config('exception.THIS_PASSWORD_RESET_TOKEN_IS_EXPIRY'));
        }
		} catch (\Exception $e) {
			$msg = $e->getMessage();
			return response()->json(['success'=>false, 'validator'=>false,'error' => $msg],config("serverConstant.STATUS_BAD_REQUEST"));
		}
		return response()->json(['success'=>true, 'response' => $passwordReset,],config("serverConstant.STATUS_OK"));
    }
	
     /**
     * Reset password
     *
     * @param  [string] email
     * @param  [string] password
     * @param  [string] password_confirmation
     * @param  [string] token
     * @return [string] message
     * @return [json] user object
     */
	 
	
    public function resetPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'userType' => 'required',
            'id' => 'required',
            'token' => 'required',
            'password' => 'required|min:6',
        ]);
		
        if ($validator->fails()) {
			$error = $validator->errors()->all();
			return response()->json(['success'=>false,'validator'=>true, 'error' => $error],config("serverConstant.STATUS_BAD_REQUEST"));	
		}
		try {
			DB::beginTransaction();
			
			$passwordReset = PasswordReset::where([
				['token', $request->token],
				['userType', $request->userType],
				['id', $request->id],
				['email', $request->email]
			])->first();
			
			if (!$passwordReset)
			{
				throw new Exception(config('exception.THIS_PASSWORD_RESET_TOKEN_IS_INVALID'));
			}
			$user = User::where('username', $request->email)->where('user_type', $request->userType)->first();

			if (!$user)
			{
				throw new Exception(config('exception.USER_DOES_NOT_EXIST_WITH_THIS_EMAIL_ID'));
			}
			$user->password = bcrypt($request->password);
			$user->save();
			$passwordReset->delete();
			$user->notify(new PasswordResetSuccess($passwordReset));
			DB::commit();
		} catch (\Exception $e) {
			DB::rollback();
			$msg = $e->getMessage();
			return response()->json(['success'=>false, 'validator'=>false,'error' => $msg],config("serverConstant.STATUS_BAD_REQUEST"));
		}
		
		return response()->json(['success'=>true, 'response' => $user,],config("serverConstant.STATUS_OK"));

    }
	
	
	
	
	
	
}
