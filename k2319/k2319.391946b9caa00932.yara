
rule k2319_391946b9caa00932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391946b9caa00932"
     cluster="k2319.391946b9caa00932"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['dccf890e493b41400902fc29ece1e0d163941903','a2f03a2f2655ada996b121bd06d5b21a8899924b','96a08cc2c41944737da9f4911f8d10d74edede48']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391946b9caa00932"

   strings:
      $hex_string = { 45323f283131312c313139293a28307842422c34292929627265616b7d3b7661722047344a35633d7b27453665273a2243222c27673663273a66756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
