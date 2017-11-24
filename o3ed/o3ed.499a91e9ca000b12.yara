
rule o3ed_499a91e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.499a91e9ca000b12"
     cluster="o3ed.499a91e9ca000b12"
     cluster_size="12"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit patched cosmu"
     md5_hashes="['1953e421714e9ef8151b4c5703ea8769','24bd16f97bd1b6906cf29fb02661cb47','f452e9dcef9f5d59a73ad2356af6c272']"

   strings:
      $hex_string = { 2544e9a3ccefd2a6582e96ba0070079e7a5e6dbf5fecbdbb9b63de0310b58f7543fb841df18a13727bd7a260393ac6c1ff9901341c3505d4c969ca851a833f6b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
