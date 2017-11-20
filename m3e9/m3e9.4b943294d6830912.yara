
rule m3e9_4b943294d6830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4b943294d6830912"
     cluster="m3e9.4b943294d6830912"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['20abafc1aed1bc4651214b263cec0d41','232246755adcd9a71741f28dd2278d8f','f90a3a0b7d762cf551704720641d6f20']"

   strings:
      $hex_string = { 841e9fadd8f88a96136e64ef5624bea293e672b2251b67a5fd48b6ac6f437eb822da9d2b92bb7a831669108c62aa5e5ca48f490519875dc34d4b7d230a866b4f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
