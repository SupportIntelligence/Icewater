
rule n3e9_3399a949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3399a949c0000b32"
     cluster="n3e9.3399a949c0000b32"
     cluster_size="48"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious socelars socstealer"
     md5_hashes="['0842b6605bddc612b0b5beb3facdb13d','187d9f389703e3e902da9238e644e13d','43ae57d387b2c72fd4ec8ae648d529a2']"

   strings:
      $hex_string = { 50020064000000703078300631c5310432a032b333f93382349434cf342335a935a336c737d53730387738b439913acd3af33a2c3be93bfb3c023d0c3d173d35 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
