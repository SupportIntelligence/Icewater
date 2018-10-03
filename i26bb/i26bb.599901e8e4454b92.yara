
rule i26bb_599901e8e4454b92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i26bb.599901e8e4454b92"
     cluster="i26bb.599901e8e4454b92"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mywebsearch malicious mindspark"
     md5_hashes="['339509ab0f0f66bfbb3cd0bbba3a39a7fa5d4d90','5b22bb15f1209e972c4ecd67f2f38125cdec5b83','32c5d9687710358fda13f7d3ec8306f2c7dcbd88']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i26bb.599901e8e4454b92"

   strings:
      $hex_string = { 08578bfa2bf185ff740e8a140e84d274078811414f4b75ee5f5e85db750649b87a000780c601005b5dc20400558becb850810000e868020000535657ff150c20 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
