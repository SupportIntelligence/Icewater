
rule n2319_4b992949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.4b992949c0000b32"
     cluster="n2319.4b992949c0000b32"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack script clicker"
     md5_hashes="['658893a84e59deb483cae452505d5a3a7e7e8524','42f0342851007a2880f9848c2ae80e0d6a497446','f6de3c282ec20d3e69a504a5d0accb34cd078a4a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.4b992949c0000b32"

   strings:
      $hex_string = { 312f672c2222293b696628212f5e5b2d5f612d7a412d5a302d39232e3a2a202c3e2b7e5b5c5d28293d5e247c5d2b242f2e74657374286329297468726f772045 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
