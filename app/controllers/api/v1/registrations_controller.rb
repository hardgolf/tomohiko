
module Api
  module V1
    
    class RegistrationsController  < ApplicationController
      before_filter :authenticate_user, except:[:create, :update, :test, :create_guess]
      http_basic_authenticate_with name: "squak_for_everyone", password: "HKP1=-098"
      respond_to :json
      rescue_from Timeout::Error, with: :handle_timeout



      def handle_timeout(exception)
        render :status=>500, :json=>{:errors=>'Time out error! This might be caused by "too large photo size" or "slow Internet connection" '}  
      end
  
      def test
        @user = ShoppingIsUser.first
        respond_to do |format|
            format.json  { render :json => @user, only:[
                                                        :appear_name, :auth_token, :created_at, :email,
                                                        :id, :is_show_marker, :is_show_online, :last_sign_out_at,
                                                        :latitude, :longitude, :location, :post_item_count, :score, :title,
                                                        :use_location_by_map, :user_url, :username, :watch_count,
                                                        :unread_post_item_messages_count, :like, :dislike, :is_found_by_others,
                                                        :is_found_by_email, :sex, :register_country
                                                       ]
                         }
          end
      end

      
      def create
        @user = ShoppingIsUser.new
        unless params[:email].present?
          render :json => { :errors => ["Email not present"] } 
          return
        end
        #@user.username = params[:email].to_s.split("@").first.gsub(/[^0-9A-Za-z]/, "")[0..7] + (ShoppingIsUser.maximum(:id).to_i + 1).to_s if params[:email].present?
        possible_username = params[:email].to_s.split("@").first.gsub(/[^0-9A-Za-z]/, "")[0..7]
        if ShoppingIsUser.exists?(:username => possible_username)
          existing_users = ShoppingIsUser.where("username LIKE '#{possible_username}%'")
          max_number = 1
          for existing_user in existing_users
            get_number = existing_user.username.gsub(possible_username,"").to_i
            max_number = get_number + 1 if get_number >= max_number 
          end
          @user.username = possible_username + max_number.to_s  
        else
          @user.username = possible_username
        end
         
        @user.email = params[:email]
        
        
        if params.has_key?(:facebook_token) && params[:facebook_token].present? && params.has_key?(:uid) && params[:uid].present? && params.has_key?(:facebook_appear_name) && params[:facebook_appear_name].present?
          if params.has_key?(:password) && params[:password].present? && params[:password].to_s.length >= 8
            @user.password = params[:password]
            @user.password_confirmation = params[:password]
          else
            @user.password = (('A'..'Z').to_a + ('a'..'z').to_a + ('0'..'9').to_a).to_a.shuffle.first((8..12).to_a.shuffle.first).join
            @user.password_confirmation = @user.password
          end
        else
          @user.password = params[:password]
          @user.password_confirmation = params[:password]
        end
        @user.appear_name = params[:appear_name]
        @user.sex = params[:sex].to_s if  params.has_key?(:sex) && params[:sex].present?
        @user.use_location_by_map = 0# params[:use_location_by_map].to_i
        @user.latitude = 0 #params[:latitude].to_f
        @user.longitude = 0 #params[:longitude].to_f
        @user.title = params[:title].to_s
        @user.location = params[:location].to_s
        @user.user_url = params[:user_url].to_s
        @user.from_web = false
        if params.has_key?(:from_web) && params[:from_web].present? && params[:from_web].to_i == 1
          @user.from_web = true 
          @user.signup_from = "web"
        end
        @user.signup_from = params[:signup_from].to_s if params.has_key?(:signup_from) && params[:signup_from].present?
        @user.register_country = params[:register_country].to_s.upcase if params.has_key?(:register_country) && params[:register_country].present?
        unless params.has_key?(:photo) && params[:photo].present?
          @user.photo_from_url params[:photo_url].to_s if params.has_key?(:photo_url) && params[:photo_url].present?
        else  
          @user.photo = params[:photo]
        end
        @user.account_type = params[:account_type].to_s if params.has_key?(:account_type) && params[:account_type].present? && (params[:account_type].to_s == 's' || params[:account_type].to_s == 'b') 
        

        #if params[:facebook_token]
        #  if params[:user][:user_social_networks_attributes]["0"][:token] && session[:oauth_token] && params[:user][:user_social_networks_attributes]["0"][:token] == session[:oauth_token]
          #@user.skip_confirmation!
        #  @social_network = true
        #  end
        #end
       
        @user.skip_confirmation!
        @user.is_set_password = true
        if @user.save
          @wish_list = @user.sis_lists.build
          @wish_list.title = "Wish List"
          unless @wish_list.save
            @user.destroy
            render :json => { :errors => ["Error: Cannot initially create Wish List"] }
            return
          end
          
          if params.has_key?(:facebook_token) && params[:facebook_token].present? && params.has_key?(:uid) && params[:uid].present? && params.has_key?(:facebook_appear_name) && params[:facebook_appear_name].present?
            @user_social_network = @user.sis_user_social_networks.build
            @user_social_network.token = params[:facebook_token].to_s
            @user_social_network.uid = params[:uid].to_s
            @user_social_network.provider = "facebook"
            @user_social_network.shopping_is_user_id = @user.id
            @user_social_network.email = params[:facebook_email].to_s  
            @user_social_network.appear_name = params[:facebook_appear_name].to_s
            @user_social_network.url = params[:facebook_url].to_s
            @user_social_network.is_connected = params[:is_connected].to_i
            @user_social_network.is_published = params[:is_published].to_i
            @user_social_network.token_expired_at = params[:facebook_token_expired_at]
            if @user_social_network.save
              #Delayed::Job.enqueue(UpdateFacebookToken.new(@user), :queue => 'worker_0')
              @user.update_attribute(:is_set_password, false)
            else
              @user.destroy
              render :json => { :errors => ["Facebook information cannot be saved"] }
              return
            end
            Delayed::Job.enqueue(SisDelayNotifyingNewUserToFacebookFriendApn.new(@user_social_network, @user), :queue => 'worker_apn')            
          end
          @user.confirm!
          @user.ensure_authentication_token!
          @user["auth_token"] = @user.authentication_token
          if Rails.env.production?
            if @user.account_type != 's' && @user.account_type != 'b'  
              @user.follow_by_id!(20) #official_user
              @user.follow_by_id!(60) #zara
              @user.follow_by_id!(9386) #shopbop
              @user.follow_by_id!(6192) #asos
              @user.follow_by_id!(5679) #amazon
              @user.follow_by_id!(118) #handm
              @user.follow_by_id!(1136) if @user.sex != 'm' #topshop
              @user.follow_by_id!(1139) if @user.sex != 'f' #topman
              @user.follow_by_id!(205) #forever21
              if @user.register_country == "TH"
                @user.follow_by_id!(219) #zalora_th
                @user.follow_by_id!(1317) # wearyouwant
                @user.follow_by_id!(2046) #lazada_beauty
                @user.follow_by_id!(2047) #lazada_fashion
              elsif @user.register_country == "SG"
                @user.follow_by_id!(6047) #zalora_sg
              elsif @user.register_country == "PH"
                @user.follow_by_id!(7549) #zalora_ph
              elsif @user.register_country == "US"
                @user.follow_by_id!(29128) #ann taylor
                @user.follow_by_id!(31928) #CoutureCandy
                @user.follow_by_id!(32119) #CUPSHE
                @user.follow_by_id!(23376) #mytheresa
                @user.follow_by_id!(29316) #OASAP
                @user.follow_by_id!(12243) #ssense
                @user.follow_by_id!(32645) #Tibi
                @user.follow_by_id!(32122) #EssentialApparel
                @user.follow_by_id!(32914) #ShoeMetro
                @user.follow_by_id!(3575) #KateSpade
                @user.follow_by_id!(3743) #Fossil
                @user.follow_by_id!(21775) #JimmyJazz
                @user.follow_by_id!(19771) #UnderArmor
                @user.follow_by_id!(28297) #LightinTheBox
                @user.follow_by_id!(218) #Nike
                @user.follow_by_id!(9386) #Shopbop
                @user.follow_by_id!(21) #Uniqlo
                @user.follow_by_id!(32646) #WristWatch
              end
            end # end if @user.account_type != 's' && @user.account_type != 'b' 
          end # end if Rails.env.production?

          ShoppingIsUserMailer.delay(:queue => 'worker_mailer').new_signup_mailer(@user)
          respond_to do |format|
            format.json  { render :json => @user, only:[
                                                        :appear_name, :auth_token, :created_at, :email,
                                                        :id, :is_show_marker, :is_show_online, :last_sign_out_at,
                                                        :latitude, :longitude, :location, :post_item_count, :score, :title,
                                                        :use_location_by_map, :user_url, :username, :watch_count,
                                                        :unread_post_item_messages_count, :like, :dislike, :is_found_by_others,
                                                        :is_found_by_email, :sex, :register_country, :account_type, :email,
                                                       ]
                         }
          end
        else
           render :json => { :errors => @user.errors.full_messages.uniq }
        end
      end # end create
      
      

      def create_guess
        @user = ShoppingIsUser.new
        guess_id = ShoppingIsUser.last.id + 1
        @user.username = "guest#{guess_id}" 
        @user.email = "guest#{guess_id}@shoppingis.me" 
        
        @user.password = "shoppingis.me"
        @user.password_confirmation = "shoppingis.me"
        
        @user.appear_name = "Guest#{guess_id}"
        
        @user.sex = params[:sex].to_s if  params.has_key?(:sex) && params[:sex].present?
        @user.use_location_by_map = 0# params[:use_location_by_map].to_i
        @user.latitude = 0 #params[:latitude].to_f
        @user.longitude = 0 #params[:longitude].to_f
        @user.title = "Guest"
        @user.location = params[:location].to_s
        @user.user_url = params[:user_url].to_s
        @user.from_web = false
        if params.has_key?(:from_web) && params[:from_web].present? && params[:from_web].to_i == 1
          @user.from_web = true 
          @user.signup_from = "web"
        end
        @user.signup_from = params[:signup_from].to_s if params.has_key?(:signup_from) && params[:signup_from].present?
        @user.register_country = params[:register_country].to_s.upcase if params.has_key?(:register_country) && params[:register_country].present?
  
        @user.account_type = "g"
        
        @user.skip_confirmation!
        @user.is_set_password = true
        if @user.save
          @wish_list = @user.sis_lists.build
          @wish_list.title = "Wish List"
          unless @wish_list.save
            @user.destroy
            render :json => { :errors => ["Error: Cannot initially create Wish List"] }
            return
          end
          
          @user.confirm!
          @user.ensure_authentication_token!
          @user["auth_token"] = @user.authentication_token
          if Rails.env.production?
            if @user.account_type != 's' && @user.account_type != 'b'  
              @user.follow_by_id!(20) #official_user
              @user.follow_by_id!(60) #zara
              @user.follow_by_id!(9386) #shopbop
              @user.follow_by_id!(6192) #asos
              @user.follow_by_id!(5679) #amazon
              @user.follow_by_id!(118) #handm
              @user.follow_by_id!(1136) if @user.sex != 'm' #topshop
              @user.follow_by_id!(1139) if @user.sex != 'f' #topman
              @user.follow_by_id!(205) #forever21
              if @user.register_country == "TH"
                @user.follow_by_id!(219) #zalora_th
                @user.follow_by_id!(1317) # wearyouwant
                @user.follow_by_id!(2046) #lazada_beauty
                @user.follow_by_id!(2047) #lazada_fashion
              elsif @user.register_country == "SG"
                @user.follow_by_id!(6047) #zalora_sg
              elsif @user.register_country == "PH"
                @user.follow_by_id!(7549) #zalora_ph
              elsif @user.register_country == "US"
                @user.follow_by_id!(29128) #ann taylor
                @user.follow_by_id!(31928) #CoutureCandy
                @user.follow_by_id!(32119) #CUPSHE
                @user.follow_by_id!(23376) #mytheresa
                @user.follow_by_id!(29316) #OASAP
                @user.follow_by_id!(12243) #ssense
                @user.follow_by_id!(32645) #Tibi
                @user.follow_by_id!(32122) #EssentialApparel
                @user.follow_by_id!(32914) #ShoeMetro
                @user.follow_by_id!(3575) #KateSpade
                @user.follow_by_id!(3743) #Fossil
                @user.follow_by_id!(21775) #JimmyJazz
                @user.follow_by_id!(19771) #UnderArmor
                @user.follow_by_id!(28297) #LightinTheBox
                @user.follow_by_id!(218) #Nike
                @user.follow_by_id!(9386) #Shopbop
                @user.follow_by_id!(21) #Uniqlo
                @user.follow_by_id!(32646) #WristWatch
              end
            end # end if @user.account_type != 's' && @user.account_type != 'b' 
          end # end if Rails.env.production?

          #ShoppingIsUserMailer.delay(:queue => 'worker_mailer').new_signup_mailer(@user)
          respond_to do |format|
            format.json  { render :json => @user, only:[
                                                        :appear_name, :auth_token, :created_at, :email,
                                                        :id, :is_show_marker, :is_show_online, :last_sign_out_at,
                                                        :latitude, :longitude, :location, :post_item_count, :score, :title,
                                                        :use_location_by_map, :user_url, :username, :watch_count,
                                                        :unread_post_item_messages_count, :like, :dislike, :is_found_by_others,
                                                        :is_found_by_email, :sex, :register_country, :account_type, :email,
                                                       ]
                         }
          end
        else
           render :json => { :errors => @user.errors.full_messages.uniq }
        end
      end # end create_guess
      


      def show          
        
        unless params.has_key?(:other_user_id) && params[:other_user_id].present?
          unless params.has_key?(:other_user) && params[:other_user].present?
            @other_user = @user
          else
            unless @other_user = ShoppingIsUser.find_by_username(params[:other_user].to_s)
              render :json => { :errors => "No user for #{params[:other_user]}" }
              return
            end
          end
        else
          unless @other_user = ShoppingIsUser.find(params[:other_user_id].to_i)
            render :json => { :errors => "No user for #{params[:other_user_id]}" }
            return
          end
        end
        
        
        
        @other_user["following_count"] = @other_user.sis_followings_count 
        @other_user["follower_count"] = @other_user.sis_followers_count 
        
        #Delayed::Job.enqueue(SisDelayUpdateAnalytic.new(@user, "registrations_show", params[:paginate_page].to_i, ""), :queue => 'worker_1')
        
        if @user.username == @other_user.username
          @other_user["is_current_user"] = true
          @other_user["is_followed"] = true

          respond_with @other_user.to_json( :methods => [:photo_url_u_350] )            
        elsif @other_user
          @other_user["is_current_user"] = false            
          @other_user["is_followed"] = @user.sis_rel_sis_user_follows.where(:follower_id =>@user.id, :followed_id => @other_user.id).exists?

          #if @is_liked = @user.relationship_user_user_likes.find_by_user_like_id(@other_user.id)
          #  @other_user["is_liked"] = true
          #else 
          #  @other_user["is_liked"] = false
          #end
          respond_with @other_user.to_json(:methods => [:photo_url_u_350])
        end            
      end # end show
      
      
      
      def edit
        
        unless @user = ShoppingIsUser.find_by_username(params[:username].to_s, :include => :sis_user_social_networks)
          render :json => { :errors => "Invalid username" } 
          return
        end
        unless @user.authentication_token == params[:auth_token].to_s
          render :json => { :errors => "Invalid auth_token" }
          return
        end
        
  
        respond_to do |format|
          format.json do
             render :json => {
               :shopping_is_users => @user.as_json(
                     :except => [
                                :photo_content_type,:photo_file_name,:photo_file_size,
                                :photo_updated_at,:photo_url, :updated_at, :oauth_token,
                                :photo_content_type, :photo_file_name, :photo_file_size, :photo_updated_at,
                                :photo_url, :updated_at, :created_at
                                ],
                     :include => {
                        :sis_user_social_networks => {
                          :only => [:appear_name, :email, :is_connected, :url, :uid, :is_published]
                        } 
                     },
                     :methods => [:photo_url_u_350]
               )
             }
          end # end format
        end # end respond_to
      end # end edit
      
      
      
      
      
      def update
        
        if params.has_key?(:id) && params[:id].present?
          @user = ShoppingIsUser.find_by_id(params[:id].to_i, :include => :sis_user_social_networks)
        else
          unless  @user = ShoppingIsUser.find_by_email(params[:email].to_s, :include => :sis_user_social_networks)
            unless @user = ShoppingIsUser.find_by_username(params[:username].to_s, :include => :sis_user_social_networks)
              render :json => { :errors => "Invalid username" }
              return
            end
          end
        end
        
        unless @user
          render :json => { :errors => "No user found" }
          return
        end

        unless @user.authentication_token == params[:auth_token].to_s
          render :json => { :errors => "Invalid auth_token" }
          return
        end
          
        email_changed = @user.email != params[:email] if params.has_key?(:email)       
        password_changed = !params[:password].empty? if params.has_key?(:password)
        
        params[:user] = Hash.new
        params[:user][:username] = params[:username].to_s if params.has_key?(:username) && params[:username].present?        
        params[:user][:appear_name] = params[:appear_name].to_s if params.has_key?(:appear_name) && params[:appear_name].present?
        params[:user][:email] = params[:email].to_s if params.has_key?(:email) && params[:email].present?
        params[:user][:current_password] = params[:current_password] if password_changed || email_changed
        params[:user][:password] = params[:password].to_s if password_changed
        params[:user][:password_confirmation] = params[:password_confirmation] if password_changed
        if password_changed
          unless params[:user][:password] == params[:user][:password_confirmation]
            render :json => { :errors => "Password not match"}
            return
          end
        end

        params[:user][:title] = params[:title].to_s if params.has_key?(:title) && (params[:title].present? || params[:title].to_s == "")
        params[:user][:location] = params[:location].to_s if params.has_key?(:location) && (params[:location].present? || params[:location].to_s == "")
        params[:user][:user_url] = params[:user_url].to_s if params.has_key?(:user_url) && (params[:user_url].present? || params[:user_url].to_s == "")
        params[:user][:is_found_by_others] = params[:is_found_by_others].to_i if params.has_key?(:is_found_by_others) && params[:is_found_by_others].present?
        params[:user][:is_found_by_email] = params[:is_found_by_email].to_i if params.has_key?(:is_found_by_email) && params[:is_found_by_email].present?        
        params[:user][:photo] = params[:photo] if params.has_key?(:photo) && params[:photo].present?
        params[:user][:register_country] = params[:register_country].to_s.upcase if params.has_key?(:register_country) && params[:register_country].present?

        if @user.account_type == "g"
          successfully_updated = @user.update_with_password(params[:user])
          @user.update_attribute(:account_type, 'n')  if params.has_key?(:email) && params.has_key?(:password)
          @user.ensure_authentication_token!
          @user["auth_token"] = @user.authentication_token
          if params.has_key?(:facebook_token) && params[:facebook_token].present? && params.has_key?(:uid) && params[:uid].present? && params.has_key?(:facebook_appear_name) && params[:facebook_appear_name].present?
            @user_social_network = @user.sis_user_social_networks.build
            raise
            @user_social_network.token = params[:facebook_token].to_s
            @user_social_network.uid = params[:uid].to_s
            @user_social_network.provider = "facebook"
            @user_social_network.shopping_is_user_id = @user.id
            @user_social_network.email = params[:facebook_email].to_s
            @user_social_network.appear_name = params[:facebook_appear_name].to_s
            @user_social_network.url = params[:facebook_url].to_s
            @user_social_network.is_connected = params[:is_connected].to_i
            @user_social_network.is_published = params[:is_published].to_i
            @user_social_network.token_expired_at = params[:facebook_token_expired_at]
            if @user_social_network.save
              #Delayed::Job.enqueue(UpdateFacebookToken.new(@user), :queue => 'worker_0')
              @user.update_attribute(:is_set_password, false)
              Delayed::Job.enqueue(SisDelayNotifyingNewUserToFacebookFriendApn.new(@user_social_network, @user), :queue => 'worker_apn')
            else
              @user.destroy
              render :json => { :errors => ["Facebook information cannot be saved"] }
              return
            end                   
          end # end if having facebook update
        else
          successfully_updated = if email_changed or password_changed
            @user.update_with_password(params[:user])
          else
            @user.update_without_password(params[:user])
          end  
           
          if successfully_updated
            @user.ensure_authentication_token!
            @user["auth_token"] = @user.authentication_token

            
            # update facebook
            if params.has_key?(:is_connected) && params[:is_connected].present? && params.has_key?(:is_published) && params[:is_published].present?
              user_facebooks = @user.sis_user_social_networks.where(shopping_is_user_id: @user.id, :provider => 'facebook')
              if user_facebooks.present?
                @user_facebook = user_facebooks.first
                @user_facebook.update_attribute(:is_connected, params[:is_connected], :is_published, params[:is_published])
              end
            end
          end 
        end # end @user.account_type == "g"
        

        if successfully_updated
          respond_to do |format|
            format.json  { render :json => @user, except:[
                                     :oauth_token,:photo_content_type,:photo_file_name,:photo_file_size,
                                     :photo_updated_at, :photo_url, :updated_at
                                     ],
                                     :methods => [:photo_url_u_350] }
          end
        else
          render :json => { :errors => @user.errors.full_messages.uniq }
        end
      
      end # end update
      
      
      
      
      
      def destroy
        
        
        @destroyed_user = @user.destroy
        respond_to do |format|
          format.json  { render :json => @destroyed_user, except:[
                                   :oauth_token,:photo_content_type,:photo_file_name,:photo_file_size,
                                   :photo_updated_at,:provider,:uid, :photo_url, :updated_at
                                   ]}
        end # end respond_to
      end # end destroy
      


      
      
      def register_facebook_account
        
        unless params.has_key?(:facebook_token) && params[:facebook_token].present?
          render :json => { :errors => "Facebook access token not present" }
          return
        end
        
        begin
          auth = Koala::Facebook::OAuth.new(ENV["FACEBOOK_SIS_APP_ID"], ENV["FACEBOOK_SIS_APP_SECRET"]) # for ShoppingIS
          new_access_info = auth.exchange_access_token_info params[:facebook_token].to_s
          new_access_token = new_access_info["access_token"]
          new_access_expired_at = Time.now + new_access_info["expires"].to_i.seconds
          @graph = Koala::Facebook::API.new(new_access_token)
          profile = @graph.get_object("me")
          if @user_facebook = @user.sis_user_social_networks.find_by_provider('facebook')
            @user_facebook.update_attributes( token:new_access_token,
                                              token_expired_at:new_access_expired_at,
                                              appear_name:profile["name"].to_s,
                                              email:profile["email"],
                                              url:profile['link'],
                                              uid:profile["id"]
                                             )
          else
            @user_social_network = @user.sis_user_social_networks.build
            @user_social_network.token = new_access_token
            @user_social_network.uid = profile["id"]
            @user_social_network.provider = "facebook"
            @user_social_network.shopping_is_user_id = @user.id
            @user_social_network.email = profile["email"]
            @user_social_network.appear_name = profile["name"].to_s
            @user_social_network.url = profile['link']
            @user_social_network.is_connected = 1
            @user_social_network.is_published = 1
            @user_social_network.token_expired_at = new_access_expired_at
            unless @user_social_network.save
              render :json => { :errors => "Facebook information cannot be saved" }
              return
            end  
          end # if @user_facebook present
          render :json => { :messages =>  "success with token update"}
          return
        rescue
          begin              
            if @user_facebook = @user.sis_user_social_networks.find_by_provider('facebook')
              @response = HTTParty.get(URI.encode('https://graph.facebook.com/' + @user_facebook.uid + '?access_token=' + ENV["FACEBOOK_SIS_APP_ID"] + '|'  + ENV["FACEBOOK_SIS_APP_SECRET"]))            
              @facebook_user_info = @response.as_json()
              @user_facebook.update_attributes( appear_name:@facebook_user_info["name"].to_s,
                                                email:@facebook_user_info["email"],
                                                url:@facebook_user_info['link'],
                                                uid:@facebook_user_info["id"]
                                              )
              render :json => { :messages =>  "success without token update"}
              return
            else
              render :json => { :errors => "Cannot find facebook account in this app" }
              return
            end
          rescue
            render :json => { :errors => "Cannot retrive Facebook user information" }
            return
          end # end begin rescue chunck 2
        end  # end begin rescue chunck 1
      
      end # end register facebook account
      
      
    end #end Class
  end #end V1
end #end Api