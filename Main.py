import phonenumber
from  phonenumber import carrier,geocoder, timezone

mobileNo = input("masukan nomer fot hack : ")
mobileNo = phonenumber.parse(mobileNo)

#mendapatkan lokasi
print(timezone.time_zones_for_number (mobileNo))

#mendapatkan provider
print(carrier.name_for_number(mobileNo, "en"))

#mendapatkan negara
print(geocoder.descripition_for_number(mobileNo, "en"))

#validating a phone number 
print("valid mobile number : ",phonenumbers.is_valid_number(mobileNo))

#cheking possibilaty number 
print("cheking possibility of number : ",phonenumbers.is_possible_number(mobileNo))
