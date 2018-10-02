
rule k3f8_1a6365668dfb5132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.1a6365668dfb5132"
     cluster="k3f8.1a6365668dfb5132"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smforw androidos smsspy"
     md5_hashes="['eee3f966332456958a45c6ee0d1d906ea09328bc','ab49627c7968034e8ab90cc6f11614f6d71bc5ae','8a32d03d1e8ba2922b6593e3de6611f6d1ab6b37']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.1a6365668dfb5132"

   strings:
      $hex_string = { 0873687574646f776e00194c6a6176612f6c616e672f537472696e674275696c6465723b00104572726f7220526573706f6e73653a200006617070656e640015 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
