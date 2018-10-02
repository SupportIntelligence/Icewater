
rule k2319_185294b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185294b9c8800b12"
     cluster="k2319.185294b9c8800b12"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['56ecb5a21fa3aaaa6c2caaf942357a301d0f80ba','3fcb5bebbc323e12d1ea005ab569333f8f2f911f','26fdda923b47a654ff160c476cf01860050a516e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185294b9c8800b12"

   strings:
      $hex_string = { 2e33364532293e3d3133393f2830783234382c313139293a28307838392c3938292929627265616b7d3b76617220483169314b3d7b274f394b273a66756e6374 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
