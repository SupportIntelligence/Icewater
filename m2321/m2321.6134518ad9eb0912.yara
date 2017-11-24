
rule m2321_6134518ad9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.6134518ad9eb0912"
     cluster="m2321.6134518ad9eb0912"
     cluster_size="19"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zegost backdoor zusy"
     md5_hashes="['0afdbb8fa9419ae192c6f48fe8ad2594','18d65f8affa85e63230fd7ac4b7ba459','a971bed46e11a5f5c60fbf4271d887be']"

   strings:
      $hex_string = { 3ff0942bc34527f55859061f9f24109e2546af612fab0089ca7e56e4547dce48904cfe252de0c77c69ac095192a29bf7e96660414dadd7f3e5cd9cecd955a8cf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
