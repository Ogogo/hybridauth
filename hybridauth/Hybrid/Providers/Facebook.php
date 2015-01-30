<?php
/*!
* HybridAuth
* http://hybridauth.sourceforge.net | http://github.com/hybridauth/hybridauth
* (c) 2009-2012, HybridAuth authors | http://hybridauth.sourceforge.net/licenses.html 
*/

/**
 * Hybrid_Providers_Facebook provider adapter based on OAuth2 protocol
 * 
 * Hybrid_Providers_Facebook use the Facebook PHP SDK created by Facebook
 * 
 * http://hybridauth.sourceforge.net/userguide/IDProvider_info_Facebook.html
 */

use Facebook\FacebookSession;
use Facebook\FacebookRequest;
use Facebook\GraphUser;
use Facebook\FacebookRequestException;
use Facebook\FacebookRedirectLoginHelper;

class Hybrid_Providers_Facebook extends Hybrid_Provider_Model
{
	// default permissions, and a lot of them. You can change them from the configuration by setting the scope to what you want/need
	public $scope = "email, user_about_me, user_birthday, user_hometown, user_website, read_stream, offline_access, publish_stream, read_friendlists";
	public $session;
	public $helper;
	
	/**
	* IDp wrappers initializer 
	*/
	function initialize() 
	{		
        $userrole_str ="";
        if(isset($_GET['user_role'])){
        	$_SESSION['user_role'] = $_GET['user_role'];        	
        }
        // USER ROLE IS CANDIDATE BY DEFAULT
        $userrole_str	= ($_SESSION['user_role']) ? "&user_role=".$_SESSION['user_role'] : "&user_role=candidate" ;
		
		if ( ! $this->config["keys"]["id"] || ! $this->config["keys"]["secret"] ){
			throw new Exception( "Your application id and secret are required in order to connect to {$this->providerId}.", 4 );
		}

		if ( ! class_exists('FacebookRequestException', false) ) {
			//require_once Hybrid_Auth::$config["path_libraries"] . "Facebook/base_facebook.php";
			//require_once Hybrid_Auth::$config["path_libraries"] . "Facebook/facebook.php";	
			/*require_once Hybrid_Auth::$config["path_libraries"] . "Facebook/FacebookSession.php";
			require_once Hybrid_Auth::$config["path_libraries"] . "Facebook/FacebookRequest.php";
			require_once Hybrid_Auth::$config["path_libraries"] . "Facebook/GraphUser.php";
			require_once Hybrid_Auth::$config["path_libraries"] . "Facebook/FacebookRequestException.php";
			require_once Hybrid_Auth::$config["path_libraries"] . "Facebook/FacebookRedirectLoginHelper.php";*/		
		}
		
		/*if ( isset ( Hybrid_Auth::$config["proxy"] ) ) {
			BaseFacebook::$CURL_OPTS[CURLOPT_PROXY] = Hybrid_Auth::$config["proxy"];
		}*/

		$trustForwarded = isset( $this->config['trustForwarded'] ) ? (bool) $this->config['trustForwarded'] : false;
		
		//$this->api = new Facebook( ARRAY( 'appId' => $this->config["keys"]["id"], 'secret' => $this->config["keys"]["secret"], 'trustForwarded' => $trustForwarded ) );

		FacebookSession::setDefaultApplication($this->config["keys"]["id"],$this->config["keys"]["secret"]);

		if ( $this->token("access_token") ) {
			$this->session = new FacebookSession($this->token("access_token"));

			/*
			$this->api->setAccessToken( $this->token("access_token") );
			$this->api->setExtendedAccessToken();
			$access_token = $this->api->getAccessToken();
			$access_token = FacebookSession::getAccessToken();

			if( $access_token ){
				$this->token("access_token", $access_token );
				$this->api->setAccessToken( $access_token );
			}

			$this->api->setAccessToken( $this->token("access_token") );
			*/
		}

		$this->helper = new FacebookRedirectLoginHelper(Hybrid_Auth::$config['base_url'].'?hauth.done=Facebook'.$userrole_str);

		// see if a existing session exists
        if ( isset( $_SESSION ) && isset( $_SESSION['fb_token'] ) ) {
          	// create new session from saved access_token
        	$this->session = new FacebookSession( $_SESSION['fb_token']);

          	// validate the access_token to make sure it's still valid
          	try {
                if ( !$this->session->validate() ) {
                 	$this->session = null;
           		}
          	} catch ( Exception $e ) {
            	// catch any exceptions
                $this->session = null;
            }
        }  // end if isset($_SESSION)

        if ( !isset( $this->session ) || $this->session === null ) {
          	// no session exists

          	try {
                $this->session = $this->helper->getSessionFromRedirect();                
           	} catch( FacebookRequestException $ex ) {
            	// When Facebook returns an error
             	// handle this better in production code              	
             	//print_r( $ex );
              	
            } catch( Exception $ex ) {
            	// When validation fails or other local issues
             	// handle this better in production code
               	//print_r( $ex );
            }
        }       
        
	}

	/**
	* begin login step
	* 
	* simply call Facebook::require_login(). 
	*/
	function loginBegin()
	{		
		$optionals  = array("scope", "redirect_uri", "display", "auth_type");

		foreach ($optionals as $parameter){
			if( isset( $this->config[$parameter] ) && ! empty( $this->config[$parameter] ) ){
				$parameters[$parameter] = $this->config[$parameter];
				
				//If the auth_type parameter is used, we need to generate a nonce and include it as a parameter
				if($parameter == "auth_type"){
					$nonce = md5(uniqid(mt_rand(), true));
					$parameters['auth_nonce'] = $nonce;
					
					Hybrid_Auth::storage()->set('fb_auth_nonce', $nonce);
				}
			}
		}

		// get the login url 
		//$url = $this->api->getLoginUrl( $parameters );

		$permissions = array(
                'user_about_me',
                //'user_activities',
                'user_birthday',
				//'user_checkins',
				'user_education_history',
				/*'user_events',
				'user_groups',
				'user_hometown',
				'user_interests',
				'user_likes',*/
				'user_location',
				/*'user_notes',
				'user_online_presence',
				'user_photo_video_tags',
				'user_photos',
				'user_relationships',
				'user_relationship_details',
				'user_religion_politics',
				'user_status',
				'user_videos',
				'user_website',*/
				'user_work_history',				
				/*'read_friendlists',
				'read_insights',
				'read_mailbox',
				'read_requests',
				'read_stream',
				'xmpp_login',
				'ads_management',
				'create_event',
				'manage_friendlists',
				'manage_notifications',
				'offline_access',
				'publish_checkins',
				'publish_stream',
				'rsvp_event',
				'sms',
				'publish_actions',
				'manage_pages'*/
				'email'
            );
		$url = $this->helper->getLoginUrl($permissions);
		
		// redirect to facebook
		Hybrid_Auth::redirect( $url );	
	}

	/**
	* finish login step 
	*/
	function loginFinish()
	{ 	
		// in case we get error_reason=user_denied&error=access_denied
		if ( isset( $_REQUEST['error'] ) && $_REQUEST['error'] == "access_denied" ){ 
			//throw new Exception( "Authentication failed! The user denied your request.", 5 );
				
			$baseUrl 	= Hybrid_Auth::$config['base_url'];
			$pos 		= strpos($baseUrl,"/social-auth");
			$websiteURL = substr($baseUrl,0,$pos);

			parent::logout();
			Hybrid_Auth::redirect($websiteURL."/user/logout" );			
		}

		// in case we are using iOS/Facebook reverse authentication
		if(isset($_REQUEST['access_token'])){
			$this->token("access_token",  $_REQUEST['access_token'] );
			//$this->api->setAccessToken( $this->token("access_token") );
			//$this->api->setExtendedAccessToken();
			//$access_token = $this->api->getAccessToken();
			if(isset($this->session)){
				$access_token = $this->session->getAccessToken();
			}

			if( $access_token ){
				$this->token("access_token", $access_token );
				//$this->api->setAccessToken( $access_token );
			}

			//$this->api->setAccessToken( $this->token("access_token") );
		}
		
		// if auth_type is used, then an auth_nonce is passed back, and we need to check it.
		if(isset($_REQUEST['auth_nonce'])){
			
			$nonce = Hybrid_Auth::storage()->get('fb_auth_nonce');
			
			//Delete the nonce
			Hybrid_Auth::storage()->delete('fb_auth_nonce');
			
			if($_REQUEST['auth_nonce'] != $nonce){
				throw new Exception( "Authentication failed! Invalid nonce used for reauthentication.", 5 );
			}
		}
		if(isset($this->session)){

			error_log( "\nHello, In loginFinish function : getAccessToken :".$this->session->getAccessToken() );					
			//error_log( "\nHello, In loginFinish function : signedRequest :".$this->session->getSignedRequest()->getUserId());
			
			$user_profile = (new FacebookRequest($this->session, 'GET', '/me'))
	                                ->execute()->getGraphObject(GraphUser::className());       

			// try to get the UID of the connected user from fb, should be > 0 
			//if ( ! $this->api->getUser() ){
			//$this->session = new FacebookSession($this->session->getAccessToken());
	        
	        error_log( "\nHello, In loginFinish function : UID of the connected user from fb :".$user_profile->getId().", Name :".$user_profile->getName() );	
			if ( ! $user_profile->getId() ){			
				throw new Exception( "Authentication failed! {$this->providerId} returned an invalid user id.", 5 );
			}

			// set user as logged in
			$this->setUserConnected();
		
			// store facebook access token 
			$this->token( "access_token", $this->session->getAccessToken() );		
		}
	}

	/**
	* logout
	*/
	function logout()
	{ 
		if($this->session){
			//$url = $this->helper->getLogoutUrl($this->session, "http://localhost.zendfactory.com/user/logout");
			
			$baseUrl 	= Hybrid_Auth::$config['base_url'];
			$pos 		= strpos($baseUrl,"/social-auth");
			$websiteURL = substr($baseUrl,0,$pos);

			//$url = $this->helper->getLogoutUrl($this->session, "http://www.zendfactory.com/user/logout");
			//$url = $this->helper->getLogoutUrl($this->session, "http://localhost.zendfactory.com/user/logout");
			$url = $this->helper->getLogoutUrl($this->session, $websiteURL."/user/logout");

			parent::logout();
			Hybrid_Auth::redirect( $url );
		}
	}

	/**
	* load the user profile from the IDp api client
	*/
	function getUserProfile()
	{		
		error_log("In getUserProfile function START ");
		// request user profile from fb api
		try{ 
			//$data = $this->api->api('/me'); 
			$user_profile = (new FacebookRequest($this->session, 'GET', '/me'))
                                ->execute()->getGraphObject(GraphUser::className());            
		}
		catch( FacebookRequestException $e ){
			throw new Exception( "User profile request failed! {$this->providerId} returned an error: $e", 6 );			
		} 

		// if the provider identifier is not received, we assume the auth has failed		
		if ( !$user_profile->getId() ){ 
			throw new Exception( "User profile request failed! {$this->providerId} api returned an invalid response.", 6 );
		}

		$fbProfileArr = $user_profile->asArray();
			
		# store the user profile.
		$this->user->profile->userRole    	= ($_SESSION['user_role']) ? $_SESSION['user_role']:"";
		$this->user->profile->identifier    = ($user_profile->getId()) ? $user_profile->getId():"";
		$this->user->profile->username      = ($user_profile->getName()) ? $user_profile->getName():"";
		$this->user->profile->displayName   = ($user_profile->getName()) ? $user_profile->getName():"";
		$this->user->profile->firstName     = ($user_profile->getFirstName()) ? $user_profile->getFirstName():"";
		$this->user->profile->lastName      = ($user_profile->getLastName()) ? $user_profile->getLastName():"";
		$this->user->profile->photoURL      = "https://graph.facebook.com/" . $this->user->profile->identifier . "/picture?width=150&height=150";
		$this->user->profile->coverInfoURL  = "https://graph.facebook.com/" . $this->user->profile->identifier . "?fields=cover";
		$this->user->profile->profileURL    = ($user_profile->getId()) ? $user_profile->getId():"";
		$this->user->profile->webSiteURL    = ($user_profile->getId()) ? $user_profile->getId():"";
		$this->user->profile->gender        = ($user_profile->getId()) ? $user_profile->getId():"";
		$this->user->profile->description   = ($user_profile->getId()) ? $user_profile->getId():"";
		$this->user->profile->email         = ($user_profile->getProperty('email')) ? $user_profile->getProperty('email'):"";
		$this->user->profile->emailVerified = ($user_profile->getProperty('email')) ? $user_profile->getProperty('email'):"";
		$this->user->profile->aboutMe 		= ($user_profile->getProperty('bio')) ? $user_profile->getProperty('bio'):"";
		$this->user->profile->region        = ($user_profile->getId()) ? $user_profile->getId():"";
		
		/*if( array_key_exists('birthday',$data) ) {
			list($birthday_month, $birthday_day, $birthday_year) = explode( "/", $data['birthday'] );

			$this->user->profile->birthDay   = (int) $birthday_day;
			$this->user->profile->birthMonth = (int) $birthday_month;
			$this->user->profile->birthYear  = (int) $birthday_year;
		}
		*/
		$this->user->profile->education		= (count($fbProfileArr['education']) > 0) ? $fbProfileArr['education'] : array();
		$this->user->profile->work         	= (count($fbProfileArr['work']) > 0) ? $fbProfileArr['work'] : array();
		
		return $this->user->profile;		
 	}

	/**
	* Attempt to retrieve the url to the cover image given the coverInfoURL
	*
	* @param  string $coverInfoURL   coverInfoURL variable
	* @retval string                 url to the cover image OR blank string
	*/
	function getCoverURL($coverInfoURL)
	{
		try {
			$headers = get_headers($coverInfoURL);
			if(substr($headers[0], 9, 3) != "404") {
				$coverOBJ = json_decode(file_get_contents($coverInfoURL));
				if(array_key_exists('cover', $coverOBJ)) {
					return $coverOBJ->cover->source;
				}
			}
		} catch (Exception $e) { }

		return "";
	}
	
	/**
	* load the user contacts
	*/
	function getUserContacts()
	{
		try{ 
			//$response = $this->api->api('/me/friends?fields=link,name'); 
		}
		catch( FacebookRequestException $e ){
			throw new Exception( "User contacts request failed! {$this->providerId} returned an error: $e" );
		} 
 
		if( ! $response || ! count( $response["data"] ) ){
			return ARRAY();
		}

		$contacts = ARRAY();
 
		foreach( $response["data"] as $item ){
			$uc = new Hybrid_User_Contact();

			$uc->identifier  = (array_key_exists("id",$item))?$item["id"]:"";
			$uc->displayName = (array_key_exists("name",$item))?$item["name"]:"";
			$uc->profileURL  = (array_key_exists("link",$item))?$item["link"]:"https://www.facebook.com/profile.php?id=" . $uc->identifier;
			$uc->photoURL    = "https://graph.facebook.com/" . $uc->identifier . "/picture?width=150&height=150";

			$contacts[] = $uc;
		}

		return $contacts;
 	}

	/**
	* update user status
	*/
	function setUserStatus( $status )
	{
		$parameters = array();

		if( is_array( $status ) ){
			$parameters = $status;
		}
		else{
			$parameters["message"] = $status; 
		}

		try{ 
			//$response = $this->api->api( "/me/feed", "post", $parameters );
		}
		catch( FacebookRequestException $e ){
			throw new Exception( "Update user status failed! {$this->providerId} returned an error: $e" );
		}
 	}

	/**
	* load the user latest activity  
	*    - timeline : all the stream
	*    - me       : the user activity only  
	*/
	function getUserActivity( $stream )
	{
		try{
			if( $stream == "me" ){
				//$response = $this->api->api( '/me/feed' ); 
			}
			else{
				//$response = $this->api->api('/me/home'); 
			}
		}
		catch( FacebookApiException $e ){
			throw new Exception( "User activity stream request failed! {$this->providerId} returned an error: $e" );
		} 

		if( ! $response || ! count(  $response['data'] ) ){
			return ARRAY();
		}

		$activities = ARRAY();

		foreach( $response['data'] as $item ){
			if( $stream == "me" && $item["from"]["id"] != $this->api->getUser() ){
				continue;
			}

			$ua = new Hybrid_User_Activity();

			$ua->id                 = (array_key_exists("id",$item))?$item["id"]:"";
			$ua->date               = (array_key_exists("created_time",$item))?strtotime($item["created_time"]):"";

			if( $item["type"] == "video" ){
				$ua->text           = (array_key_exists("link",$item))?$item["link"]:"";
			}

			if( $item["type"] == "link" ){
				$ua->text           = (array_key_exists("link",$item))?$item["link"]:"";
			}

			if( empty( $ua->text ) && isset( $item["story"] ) ){
				$ua->text           = (array_key_exists("link",$item))?$item["link"]:"";
			}

			if( empty( $ua->text ) && isset( $item["message"] ) ){
				$ua->text           = (array_key_exists("message",$item))?$item["message"]:"";
			}

			if( ! empty( $ua->text ) ){
				$ua->user->identifier   = (array_key_exists("id",$item["from"]))?$item["from"]["id"]:"";
				$ua->user->displayName  = (array_key_exists("name",$item["from"]))?$item["from"]["name"]:"";
				$ua->user->profileURL   = "https://www.facebook.com/profile.php?id=" . $ua->user->identifier;
				$ua->user->photoURL     = "https://graph.facebook.com/" . $ua->user->identifier . "/picture?type=square";

				$activities[] = $ua;
			}
		}

		return $activities;
 	}
}
