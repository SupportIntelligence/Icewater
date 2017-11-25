
rule o3e9_585b3ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.585b3ec9cc000b12"
     cluster="o3e9.585b3ec9cc000b12"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur ransom"
     md5_hashes="['1c25313495aa043c3cf294e971c596f0','9b249ec48bd75a73cbd3c3703eec4d09','ca8ebb83e2fa3cdfedd05933c810774d']"

   strings:
      $hex_string = { 1c3dd0ff2149dbff2754e5ff2a5cedff2b5deeff2856e8ff234cdeff1d40d3ff7b6386fffee3c8fffcd1beffdd978bff331a0d8c351b0e3c3f1b1b0e7f7f7f01 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
