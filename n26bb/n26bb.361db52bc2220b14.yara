
rule n26bb_361db52bc2220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.361db52bc2220b14"
     cluster="n26bb.361db52bc2220b14"
     cluster_size="99"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="auslogics malicious silentinstaller"
     md5_hashes="['999bdcfdb6f5fca193761ca5092678053334bf6e','d1e4a5bb40b153170ef8a3bc01c3ffb3c6e374aa','55d0a19f5e4fb56e3b658790a04a085b29e149c2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.361db52bc2220b14"

   strings:
      $hex_string = { 83fb09773e8d3cbf01ff01df668b1e83c6026685db75e4fecc7502f7df0fbec001f85251e848000000595afecd740d83c40c31f6d1ee89325f5e5bc3d9e0ebef }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
