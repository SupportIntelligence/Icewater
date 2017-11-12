
rule n3e9_251d9cc9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.251d9cc9cc000b32"
     cluster="n3e9.251d9cc9cc000b32"
     cluster_size="1543"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['004cc3a3df5db95a20dce685ccec619a','00debf1320a9e0c7295d34a20830a604','07f24b71908ca6ed0e019b314184f4ea']"

   strings:
      $hex_string = { 7711e81e84b48219b52d56bdf99525b02a4e37aee6b14fdf678e04585ed8f1302be1830daea4abac9d84c1ad5043833b79d4c5d8e761420cb3b119d716c7a7b1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
