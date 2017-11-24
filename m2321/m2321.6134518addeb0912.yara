
rule m2321_6134518addeb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.6134518addeb0912"
     cluster="m2321.6134518addeb0912"
     cluster_size="14"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zegost backdoor zusy"
     md5_hashes="['0c736f7ba56fe61e5c8bcf0d11147545','12a781d2f75a2e0882f2955a5e2f280c','fb440835a5ed84f3ec637e02a0379257']"

   strings:
      $hex_string = { 3ff0942bc34527f55859061f9f24109e2546af612fab0089ca7e56e4547dce48904cfe252de0c77c69ac095192a29bf7e96660414dadd7f3e5cd9cecd955a8cf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
