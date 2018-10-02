
rule k26bb_193e69e359b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.193e69e359b2f316"
     cluster="k26bb.193e69e359b2f316"
     cluster_size="203"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore dealply malicious"
     md5_hashes="['8ed8401caaad49cc05a0ab346172b69c62406655','dcf45dfdecbcb6b158a77e35165bdca649536668','60267a08a21c3f0c73981926afc45a12071bba1f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.193e69e359b2f316"

   strings:
      $hex_string = { 0380eb208a7fff80ff61720880ff7a770380ef2038fb74d80fb6c30fb6d729d05b5f5ec39083c4f86a0089442404c6442408008d4c24048bc2bac04c4000e8f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
