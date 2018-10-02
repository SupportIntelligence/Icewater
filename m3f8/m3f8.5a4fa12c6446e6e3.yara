
rule m3f8_5a4fa12c6446e6e3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.5a4fa12c6446e6e3"
     cluster="m3f8.5a4fa12c6446e6e3"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos asacub"
     md5_hashes="['cf516b0c2b88ec7ef6c1717537d52b6e346c6334','d18c31b4778dd49d46839a0ccdf7d6d0d7d9152b','8b881fae3e9414fbff08aabe6efab832cfe61d9d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.5a4fa12c6446e6e3"

   strings:
      $hex_string = { 70686963732f586665726d6f64653b00114c616e64726f69642f6e65742f5572693b001a4c616e64726f69642f6f732f4275696c642456455253494f4e3b0012 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
