
rule k2319_2916d9eb86220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2916d9eb86220932"
     cluster="k2319.2916d9eb86220932"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik diplugem"
     md5_hashes="['91b9d65ca49699b245da6b0b0683833edcfd072f','4c33c5626fc83ffff2c306fce578f0248d445255','cc37a85d08ca60a22f74c5f77135637ed1a289c5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2916d9eb86220932"

   strings:
      $hex_string = { 2e293c3d37373f28307846442c313139293a2830783135422c3930292929627265616b7d3b7661722066335432643d7b274b3664273a66756e6374696f6e2875 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
