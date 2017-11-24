
rule i3ed_05eb47a32a410132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.05eb47a32a410132"
     cluster="i3ed.05eb47a32a410132"
     cluster_size="34"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bundpil gamarue zusy"
     md5_hashes="['07172e4d135cf2caad51553bbf68d984','0853016af15df18b70a27c58f44dae22','73c1bbbd3e976ada975c9ecf06dbdb2e']"

   strings:
      $hex_string = { 5348454c4c33322e646c6c005e026672656500000f015f696e69747465726d0091026d616c6c6f6300009d005f61646a7573745f6664697600004d5356435254 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
