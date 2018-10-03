
rule k2319_181c3ab9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181c3ab9c8800912"
     cluster="k2319.181c3ab9c8800912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b462655593e903674aeec9f714e62f0837b4482a','92eb3ba5a2b400048744d8c242cdefc8b8208acf','bed917c7f219dcbc1ea0c68e37819b5e97e442e0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181c3ab9c8800912"

   strings:
      $hex_string = { 43422c3078323239293f28307839442c274f27293a28352e3545312c3078314437292929627265616b7d3b766172206b3371313d7b277538273a66756e637469 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
