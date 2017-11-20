
rule m3e9_6b6f27a4ac544eba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b6f27a4ac544eba"
     cluster="m3e9.6b6f27a4ac544eba"
     cluster_size="26"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['12580903e4e0873a5e25c32ade45b14c','13d1f4cd6d2e06a322def9c286a4f0d2','cb499327d745d91e6725cb03c86698c4']"

   strings:
      $hex_string = { 38f1179eb10f0703f742e1aa85b048532ff4efbb78e4edb6c562146cf683d7c4fd348b6492894fda060222448699c01675e5dc6e70a17c1dff244daf25e06b05 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
