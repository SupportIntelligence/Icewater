
rule m2318_6b392012d7d30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.6b392012d7d30b32"
     cluster="m2318.6b392012d7d30b32"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['199575188ca919a7750c63ce1114efec','19d5e8f2027d9017c2e41d9a00179040','d4449a299f722f9af1695b5923d4e22e']"

   strings:
      $hex_string = { 654f626a6563742822575363726970742e5368656c6c22290d0a5753487368656c6c2e52756e2044726f70506174682c20300d0a2f2f2d2d3e3c2f5343524950 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
