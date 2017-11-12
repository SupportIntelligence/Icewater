
rule m3e9_431e9ec9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.431e9ec9cc000b32"
     cluster="m3e9.431e9ec9cc000b32"
     cluster_size="31"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack virut"
     md5_hashes="['115c088d4acffde5fd02dcc0903386e8','24ff8ac004cb80cf7914acf6db7efe3e','d0f8ea28adecfc4c45798482c7cd95db']"

   strings:
      $hex_string = { 7b7def7ca37f377ecb790cd66de5e9f4650be11a5d29d938554fd18d6373d476b8903c91c0924493c8944c95d0965497d8985c99e09a649be89c6c9df09e749f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
