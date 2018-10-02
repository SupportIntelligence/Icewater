
rule k2319_5a589ae9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a589ae9c8800912"
     cluster="k2319.5a589ae9c8800912"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b2a757a3b8cec36faa9a7e6c283fdece9a8aa366','ba26e89edfb28257fb01bdafff03ccaae73ed8c9','806b8edb3079334a5f099d4b519f1c3d83c37656']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a589ae9c8800912"

   strings:
      $hex_string = { 77696e646f773b666f72287661722063367920696e207139493679297b6966286336792e6c656e6774683d3d3d282830783138382c3231293e3d30783134443f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
