
rule mfc8_039db28dc6620932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=mfc8.039db28dc6620932"
     cluster="mfc8.039db28dc6620932"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos opfake fakeinst"
     md5_hashes="['40e99d149a76c205edfdd35be92aed3a887f27b9','a24adf613670536239c7bcd37e068a1528c078ba','3bbcec98e6ffcafe73e9b71110e052f85aff7f3f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=mfc8.039db28dc6620932"

   strings:
      $hex_string = { 25620191c8389848444189b809a612165127d76be714a31d3a0250f778e8cb66f9fd93839ddf4c4ebd0d4d10af59056afa1e600b32439030375ebbad94829aac }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
