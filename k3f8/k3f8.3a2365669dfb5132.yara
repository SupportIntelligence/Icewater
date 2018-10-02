
rule k3f8_3a2365669dfb5132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.3a2365669dfb5132"
     cluster="k3f8.3a2365669dfb5132"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smforw androidos smsspy"
     md5_hashes="['f24537e9fb5d34dd63139218b41617a24320507e','15337154e927d926f487555408bc134624ea2cd6','476ec9e032cc5339e5f673c7fe974a34d005a7eb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.3a2365669dfb5132"

   strings:
      $hex_string = { 0873687574646f776e00194c6a6176612f6c616e672f537472696e674275696c6465723b00104572726f7220526573706f6e73653a200006617070656e640015 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
