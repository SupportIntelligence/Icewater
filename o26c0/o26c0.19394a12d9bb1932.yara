
rule o26c0_19394a12d9bb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.19394a12d9bb1932"
     cluster="o26c0.19394a12d9bb1932"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious heuristic"
     md5_hashes="['eefa8eb960030cfa7bbd8ed1f4d0b356dfe9dfcd','83d5f74c8f9351bd1139425d978a353b7c05f2d5','8d1c60788d65f4ccc7ea01ab9644a0a5b572e0f9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.19394a12d9bb1932"

   strings:
      $hex_string = { fc7f50fb1d3f10e06c191f857aca9b93f87d80534e95b306785e590f2755186a57ae00174cc9efb86eea69b5f3587797cee2bdab7ee1ec04a4c0e4d89f525d2a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
