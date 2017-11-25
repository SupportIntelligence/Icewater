
rule m3e9_0691534b6b9d5c53
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0691534b6b9d5c53"
     cluster="m3e9.0691534b6b9d5c53"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar midie scudy"
     md5_hashes="['281b41a032caaef9d4bda3f03aa3674e','57d4caabd5fee3163e2f6ca0768dc864','e4d7b1142e2c86a56a90221536a9fdf0']"

   strings:
      $hex_string = { 3785aa904d662e0af1dd9b5805d4adac99316b8e5c9e0f23ab873ca53e427b8da6b4be16f603f971fd8c6080020e38119491e53db7d0d9a1bc6a786cc9a8349a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
