
rule o3e9_019890b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.019890b9c8800b32"
     cluster="o3e9.019890b9c8800b32"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke miniduke"
     md5_hashes="['12042e38b51f9de455707f22caea29ac','71a9c04822c525c2af3e98e3c288c13f','e851c296f98775da1885431b7292e44f']"

   strings:
      $hex_string = { f58176f63121c06001e69dbc29b9db8b7e0e128a09f4881726b20ca0fd146db78c97d8f01f4d901c486a723b6cb31b58740aab7c55c4c2ae382a457f4fc837ec }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
