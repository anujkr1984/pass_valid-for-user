class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  validate :password, if: :valid_password?
  
  private

  def valid_password?
    if password
      errors.add(:password, 'Minimum 6 characters is required') if password.length < 6
      errors.add(:password, 'Id & password can not be same') if password == self.email
      errors.add(:password, 'should be start from an alphabet') unless password.match?(/\A[a-zA-Z]/)
      errors.add(:password, 'should be end with an alphabet') unless password.match?(/[a-zA-Z]\z/)
    end      
  end       
end
