
rule j26bf_21b3a00080001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.21b3a00080001132"
     cluster="j26bf.21b3a00080001132"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo malicious agen"
     md5_hashes="['e113dcbabbc97ceb60ac3b217af22487bd91e19b','af17011e7be347e678dda4c7bd43a315726a8a87','86afaf0153e7525590a32c5aef881e1ad919f3b1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.21b3a00080001132"

   strings:
      $hex_string = { 7269627574650053797374656d2e52756e74696d652e496e7465726f70536572766963657300436f6d56697369626c6541747472696275746500477569644174 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
