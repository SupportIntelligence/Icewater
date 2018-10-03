
rule k2319_7b0cea49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.7b0cea49c0000b12"
     cluster="k2319.7b0cea49c0000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector html iframe"
     md5_hashes="['2324290c6981c82049c5712eae6d5b5a546cff74','2f00f1237533f67ad72d2ed3ecb1f30eda0e9363','cec31f45963fcf1a88d1519a2fc07b01b17fef9f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.7b0cea49c0000b12"

   strings:
      $hex_string = { 6e673d22302220636c6173733d22626f785f77696474685f6c656674223e0a093c74723e3c74643e3c696d67207372633d22696d616765732f7370616365722e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
