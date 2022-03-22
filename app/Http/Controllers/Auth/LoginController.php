<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Input;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use App\Models\Buyer;
use App\Models\Seller;
use App\Models\FreeTrialPackage;
use App\Models\BidPackageUserMapping;
use App\Mail\ActivateBuyerAccount;
//use Illuminate\Support\Facades\Auth;
use JWTAuth;
use Auth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Redirect;
use Exception;
use Validator;
use Socialite;
use DB;
use Mail;
use Carbon\Carbon;
use Stripe;
use Log;
use Cookie;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
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
        $this->middleware('guest')->except('logout');
    }
	
	public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|email',
            'password' => 'required',
            'user_type' => 'required',
            'status' => 'required',
        ]);
        if ($validator->fails()) {
			$error = $validator->errors()->all();
			return response()->json(['success'=>false,'validator'=>true, 'error' => $error],config("serverConstant.STATUS_BAD_REQUEST"));	
		}
		
        try{
			log::debug('login');
			$email = Input::get('username');
			$password = Input::get('password');
			$user_type = Input::get('user_type');
			$user = User::where('username',$email)->where('user_type',$user_type)->whereNull('deleted_at')->first();
            if($user)
            {
				if($user->status == 0)
				{
				throw new Exception(config("exception.USER_INACTIVE"));
				}
				if($user->user_status == 'ACTIVE')
				{
					log::debug('test');
					$input = $request->only('username', 'password','user_type','status');
					
					$jwt_token = null;
					if (!$jwt_token = JWTAuth::attempt($input)) {
						throw new Exception(config("exception.INVALID_USER_NAME_OR_PASSWORD"));
					}
					
					$user->update(['login_status'=>'ONLINE']);
				}
				else
				{
					throw new Exception(config("exception.YOUR_ID_HAS_BEEN_BLOCKED_BY_ADMIN_PLEASE_CHECK_YOUR_MAIL"));
				}
            }
            else
            {
				throw new Exception(config("exception.USER_DOES_NOT_EXIST_WITH_THIS_EMAIL_ID"));
            }
        }
        catch (\Exception $e) {
            return response()->json(['success'=>false, 'validator'=>false,'error' => $e->getMessage()],config("serverConstant.STATUS_BAD_REQUEST"));
        } 
		return response()->json(['success'=>true, 'response' => $user, 'token'=>$jwt_token],config("serverConstant.STATUS_OK"));
    }

	/**
     * Function for seller changeLoginStatus
     */
    public function changeLoginStatus($loginStatus)
	{
		try
		{
			$profile = json_decode(Cookie::get('profile'));
			$user = User::where('id',$profile->id)->whereNull('deleted_at')->first();

			DB::beginTransaction();
			$user->update(['login_status'=>$loginStatus]);
			DB::commit();
		}
		 catch (\Exception $e) 
		{
            DB::rollback();
			return response()->json(['success'=>false, 'validator'=>false,'error' => $e->getMessage()],config("serverConstant.STATUS_BAD_REQUEST"));
        } 
		return response()->json(['success'=>true, 'response' => $user,config("serverConstant.STATUS_OK")]);
       
    }
	
	/**
	  * Redirect the user to the Google authentication page.
	  *
	  * @return \Illuminate\Http\Response
	  */
	public function redirect($provider,Request $request)
	{
		log::debug('redirect to provi');
		log::debug($provider);
		log::debug($request->user_type);
		session(['user_type' => $request->user_type]);
		return Socialite::driver($provider)->redirect();
	}
	
	/**
     * Obtain the user information from Google.
     *
     * @return \Illuminate\Http\Response
     */
    public function Callback($provider)
    {
		try {
			DB::beginTransaction();
			//$user_type = 'BUYER';
			$user_type = session('user_type');
			log::debug('$user_typeaa');
			log::debug($user_type);
			log::debug($provider);
            $user = Socialite::driver($provider)->user();
			/* var_dump($user);
			die; */
				if($provider == 'facebook')
				{
					log::debug('$proo');
					log::debug($provider);
					$checkIfExist = User::where('provider',$provider)
										->where('provider_id',$user->user['id'])
										->where('user_type',$user_type)
										->first();
					if($checkIfExist)
					{
						$authUser = $checkIfExist;
					}
					else
					{
						log::debug('return fb form page');
						return view('pages.complete_facebook_registration',compact('user','user_type','provider'));
					}
				}
				else
				{
					$authUser = $this->findOrCreate($user,$provider,$user_type);
				}

				$userTableInfo = User::findOrFail($authUser->id);
				
				log::debug('$authUser');
				log::debug($authUser);
			   // Auth::loginUsingId($authUser->id);
			   //return redirect('/');
				
				$password = 'servbetter'. $provider . '@123';
				
				$loginInfo = [
					"username" => $authUser->username,
					"password" => $password,
					"user_type" => $authUser->user_type,
					"status" => 1,
				];
				log::debug($loginInfo);
				$response = $this->postCURLWithoutAuth('api/login',$loginInfo);
				if($response && $response->content && $response->content->success)
				{	
						log::debug('$response');
					if($authUser->user_type == "BUYER")
					{
						$authResponse = Auth::guard('buyerweb')->attempt($loginInfo,Input::get('remember_token'));
					}
					else if($authUser->user_type == "SELLER")
					{
						$authResponse = Auth::guard('sellerweb')->attempt($loginInfo,Input::get('remember_token'));
					}
					
					//Cookie::queue('token', trim($response->content->token));
					Cookie::queue('token', trim($response->content->token), 1000, null, null, false, false);
					$userInfo = $response->content->response;
					$responseProfile = $this->getCURLWithAuth('api/profileByUserId/'.$userInfo->id.'/'.$userInfo->user_type,'');

					if($responseProfile && $responseProfile->content && $responseProfile->content->success)
					{
						log::debug('$response profile');
						/* var_dump($responseProfile->content->response);
						die; */
						//$cardInfo = $this->getAllCards($responseProfile->content->response->stripe_id);
						Cookie::queue('profile', json_encode($responseProfile->content->response),1000, null, null, false, false);
						
						$urlLogin = "";
						
						log::debug('urlLogin');
						//
						if($authUser->user_type == "BUYER")
						{
							$user_type_main = $responseProfile->content->response->buyer_type;
						}
						else if($authUser->user_type == "SELLER")
						{
							$user_type_main = $responseProfile->content->response->seller_type;
						}
						log::debug($user_type_main);
						
						if($user_type_main && $user_type_main != null)
						{
							if($urlLogin && $urlLogin != "")
							{
								log::debug('yes urlLogin');
								return redirect($urlLogin);
							}
							else
							{
								log::debug('redireeeexct');
								log::debug('redirectning');
								return redirect('/');
							}
						}
						else
						{
							$userInfo = $responseProfile->content->response;
							return view('pages.complete_social_registration',compact('userInfo'));
						}
					}
					else{				
						$exceptionVal = $this->getErrorMessage($responseProfile);
						throw new Exception($exceptionVal);
					}
				}
				else{				
					$exceptionVal = $this->getErrorMessage($response);
					throw new Exception($exceptionVal);
				}			
        } 
		catch (Exception $e) {
			DB::rollback();
			log::debug($e);
			$errorMessage = $e->getMessage();
			log::debug($errorMessage);
            return redirect('/login/'.$provider);
			//return redirect()->back()->withErrors(["error" => $errorMessage]);
        }
        
    }
	
	public function findOrCreate($user,$provider,$user_type)
	{
		  /* try {
			DB::beginTransaction();  */  
			$checkIfExist = User::where('username', $user->email)->where('user_type',$user_type)->whereNull('deleted_at')->first();

			log::debug('$checkIfExist');
			log::debug($checkIfExist);

			if($checkIfExist){
				log::debug('$existingUser google user');
				$checkIfExist->provider = $provider;
				$checkIfExist->provider_id = $user->user['id'];

				$checkIfExist->save();
				DB::commit();
				return $checkIfExist;
			}
			log::debug('create google user');
			//Create Buyer Or Seller
			$registration_date = date('Y-m-d');
			if($user_type == "BUYER")
			{
				$model = new Buyer;
				$model->buyer_status = '0';

			}
			else if($user_type == "SELLER")
			{
				$model = new Seller;
				$model->seller_status = '0';
			}
			
			$model->fname = $user->user['given_name'];
			$model->lname = $user->user['family_name'];
			$model->email = $user->getEmail();
			$model->registration_date = $registration_date;
			$model->activation_code = str_random(25);

			$model->save();
			
			if($user_type == "BUYER")
			{
				$user_code = 'B'. substr(strtoupper($user->user['given_name']), 0, 1) . sprintf("%06d", $model->buyer_id);
				$model->buyer_code = $user_code;
				$entity_id = $model->buyer_id;
			}
			else if($user_type == "SELLER")
			{
				$user_code = 'S'. substr(strtoupper($user->user['given_name']), 0, 1) . sprintf("%06d", $model->seller_id);
				$model->seller_code = $user_code;
				$entity_id = $model->seller_id;
			}
			$password = 'servbetter'. $provider . '@123';
			log::debug($password);
			$model->password = Hash::make($password);
		
			$model->save();
			
			/** Added to users table **/
			$userModel = new User;
			$userModel->user_type = $user_type;
			$userModel->entity_id = $entity_id;
			$userModel->username = $model->email;
			$userModel->password = Hash::make($password);
			$userModel->two_step_authentication = '0'; 
			$userModel->status = '1';
			$userModel->provider = $provider;
			$userModel->provider_id = $user->user['id'];

			Stripe\Stripe::setVerifySslCerts(false);
			$userModel->createAsStripeCustomer();
			$userModel->save();
			
			//Adding trial_package for seller
			if($user_type == "SELLER")
			{
				$sellerInfo = Seller::findOrFail($entity_id);
				$trial_package = FreeTrialPackage::whereNull('deleted_at')->orderByRaw('created_at DESC')->first();
				if($trial_package)
				{
					log::debug('trial_package');
					log::debug($trial_package);
					for($i = 0; $i< $trial_package->month_period ; $i++)
					{
						if($i == 0)
						{
							$package_status = "ACTIVE";
							$start_date = Carbon::now()->toDateTimeString();
						}
						else
						{
							$package_status = "PENDING";
							$start_date = null;
						}
						
						$mappingInfo = [
							'free_trial_package_id' => $trial_package->free_trial_package_id,
							'user_id' => $userModel->id,
							'package_status' => $package_status,
							'start_date' => $start_date,
						];
						BidPackageUserMapping::create($mappingInfo);
					}
					
					//added free bids
					$model->bid_points = $trial_package->bid_points;
					$model->save();
				}
			}
		 	DB::commit();
			return $userModel;
		/*   }
		catch (Exception $e) {
			DB::rollback();
            return redirect('/login/'.$provider);
        }   
		 */
        //return User::create($input);
        
	}
	
	
}
