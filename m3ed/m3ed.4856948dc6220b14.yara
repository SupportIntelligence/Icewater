
rule m3ed_4856948dc6220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4856948dc6220b14"
     cluster="m3ed.4856948dc6220b14"
     cluster_size="4"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['97f28bde0da24aea5b9fd3d187cf74be','a904bf6ed092825c96ac11ee987f1132','ecf50d6d942159f8cbf524b2ea1e6c85']"

   strings:
      $hex_string = { b7972d6d41b173f8f8605392401f0b897fd0286c824b19a05f86685ae8278a76c823fede62c41b17d79a26344ebeb090721c6e0fb6cd9ea4ea8c3bb5d62b7874 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
