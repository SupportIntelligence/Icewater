
rule o26bb_594a5c8cee610932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594a5c8cee610932"
     cluster="o26bb.594a5c8cee610932"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious bcyeq"
     md5_hashes="['0b962ee872d9dfec4a3ddda699974fdf79d473cf','a8172405cdcecc123a9c01df1f9c318e218d2ebc','79ef93b46f33ada3cf9262222f054776beee7e71']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594a5c8cee610932"

   strings:
      $hex_string = { 55544638537472696e67e9fd0200fc2340000a0d52617742797465537472696e67ffff020000142440001408504c6f6e67496e749c1040000200282440001405 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
