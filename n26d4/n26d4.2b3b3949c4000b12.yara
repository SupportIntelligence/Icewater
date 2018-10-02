
rule n26d4_2b3b3949c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.2b3b3949c4000b12"
     cluster="n26d4.2b3b3949c4000b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cloudatlas malicious neoreklami"
     md5_hashes="['8a4c0c4ad9bae417fc60b3d79ea71afa8a8655d1','91f6d8dc1dcf25c56417524d6ae026fe0acb894a','4b4eae11adfbece9ed8165ffbfa293373cb5e328']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.2b3b3949c4000b12"

   strings:
      $hex_string = { 7f04008bc27e0e8b0f803c082d7409403b47047cf483c8ff85c0c745b8d55b880fc745a85b5312ca0f98c3c745ac4f0f000080c32d8955b06a02885d9059eb0a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
