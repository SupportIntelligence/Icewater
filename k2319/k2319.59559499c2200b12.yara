
rule k2319_59559499c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.59559499c2200b12"
     cluster="k2319.59559499c2200b12"
     cluster_size="43"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5d428d7d05f499fcd3137fa44e36fa39d7a43326','ada8d193adf929b8e43c569a503fa31800fddc0e','ad2f9a0d4452f5cbe61bb0c2b04cb683ae053b79']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.59559499c2200b12"

   strings:
      $hex_string = { 3a2833332e3545312c342e38384532292929627265616b7d3b76617220653674365a3d7b27453474273a2277222c2741315a273a66756e6374696f6e28542c43 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
