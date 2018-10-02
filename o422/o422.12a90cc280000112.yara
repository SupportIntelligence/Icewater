
rule o422_12a90cc280000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o422.12a90cc280000112"
     cluster="o422.12a90cc280000112"
     cluster_size="315"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy adposhel malicious"
     md5_hashes="['e9695555c8aa41f2b7777ea58ab7312663493b3f','f5241e0d2db5d947accc78e466268c28e0f935c4','296ce592485abdb31dfc28838dc7c7ef1a81a18d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o422.12a90cc280000112"

   strings:
      $hex_string = { e9325ed570bc36771599aef1f83f6c97e3a213cc853cc6ff910b5b14f93f2325582e79d69dbce5c5cdb03737f93fbb7eb581c75f67bc0f52c8cb445af93f39f0 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
