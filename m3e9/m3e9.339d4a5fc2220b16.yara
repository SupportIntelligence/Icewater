
rule m3e9_339d4a5fc2220b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.339d4a5fc2220b16"
     cluster="m3e9.339d4a5fc2220b16"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['01ce179c2f6b243858c39a1e4d609b95','2bc52d61ef2aa250fcc7718034cf269a','34e9a9d8734244d08c7b3850af6d3e99']"

   strings:
      $hex_string = { a6b7a5bfe60bda76c0f38681c28c0063e00e013658871ba317b9082ed7203bfd97f640ab0cbee947bb108852787a37ed1fc81e0d3fa70c6e8f853349f8cc7c71 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
