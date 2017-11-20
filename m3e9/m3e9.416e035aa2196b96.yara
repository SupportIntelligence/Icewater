
rule m3e9_416e035aa2196b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.416e035aa2196b96"
     cluster="m3e9.416e035aa2196b96"
     cluster_size="23"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis adload clickdownload"
     md5_hashes="['17badefd68bb1f8639a403a1f78dcaae','19f750383e1179e3ce8a19624da7ea7e','bfbe35c03c5bd0721c7b3fe2bca20ddf']"

   strings:
      $hex_string = { 4feb4994f7477edd83fd3438c65d54abf4aff551a08a65230a9e42b930e85041d5b726a8951d328c5619d38e00914cdc1311e39d661a0b88bcd6cd396aa6beaa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
