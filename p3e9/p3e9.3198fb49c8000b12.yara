
rule p3e9_3198fb49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.3198fb49c8000b12"
     cluster="p3e9.3198fb49c8000b12"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur polyransom"
     md5_hashes="['73ca0d5adec0b0ce08ec739a25b4895f','a12768719c116e49d91d99429f674468','d52e368b0ba2b4d86e0f11de22675575']"

   strings:
      $hex_string = { f3cdabfff0caa9ffedc7a8ffe9c3a5ffe6c0a3ffe2bca1ffdeb89fffdab49effd6b19bffd3ad99ffcfaa97ffcca696ffc9a494ffb17f73ff030303230b0b0b0b }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
