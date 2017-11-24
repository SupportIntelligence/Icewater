
rule k3e9_199a9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.199a9cc9cc000b12"
     cluster="k3e9.199a9cc9cc000b12"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos qqhelper"
     md5_hashes="['14c251ccd82e6935ab8627e11777a3af','29890d0b356b456afbfabcb241ce97a0','fbfcb10e74d778424eae64ff8dddf12f']"

   strings:
      $hex_string = { 8e5a785b24761eeb68d33d2c741b1c1fa18231220eea4c6e61ccdf73f84d7986c116bf5eb6e54630e09e66fc2e67920df92ae18b6043ee2f23bcbbde281bf407 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
