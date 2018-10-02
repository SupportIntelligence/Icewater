
rule m2319_39394cb0d9b2e132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.39394cb0d9b2e132"
     cluster="m2319.39394cb0d9b2e132"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="inor script fundf"
     md5_hashes="['0935ade7b006809a481c635506e02ea8da846fcf','433da84f63e138238bc7c720cb339ae75f67a4d4','7306221deb34e5a2c8f664d56b1d296b40051c9e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.39394cb0d9b2e132"

   strings:
      $hex_string = { 312f672c2222293b696628212f5e5b2d5f612d7a412d5a302d39232e3a2a202c3e2b7e5b5c5d28293d5e247c5d2b242f2e74657374286329297468726f772045 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
