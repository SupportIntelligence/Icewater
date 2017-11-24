
rule k3e9_099a9cc9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.099a9cc9cc000b32"
     cluster="k3e9.099a9cc9cc000b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['0b795afe24929eeeaaffb5106eff824d','ab1fcbd7200e95108a1b5339971e93b2','d8c00d6e46cddbd7ca3f8c29a62384ba']"

   strings:
      $hex_string = { 8e5a785b24761eeb68d33d2c741b1c1fa18231220eea4c6e61ccdf73f84d7986c116bf5eb6e54630e09e66fc2e67920df92ae18b6043ee2f23bcbbde281bf407 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
