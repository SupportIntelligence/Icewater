
rule m2321_2998118dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2998118dc6220b32"
     cluster="m2321.2998118dc6220b32"
     cluster_size="21"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['21bb6bc71145482f1e9150e0dde9db22','2310e27790092d1e3799f3c63fec3c34','b7e628843d10a8651883d2c9fd56fd70']"

   strings:
      $hex_string = { 29511f7fa0a9ac6a24f798543910770a0f172e57b6c9b9c75c1add16e630906d9730130b70fc6e47e99488df7d58f9e3a25d2ff276b169bb67aef115966121ed }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
