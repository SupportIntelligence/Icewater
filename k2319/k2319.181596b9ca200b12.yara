
rule k2319_181596b9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181596b9ca200b12"
     cluster="k2319.181596b9ca200b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['8e1b6a2b20b194ee6ed4fc19aeb80e39e7530c09','6a97973b5afcc9c14c2b2328708c3b3aa243a480','7bb94e168f97b11615eda10d98739496348aa6c7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181596b9ca200b12"

   strings:
      $hex_string = { 3631293f2277223a2830783133452c3635292929627265616b7d3b666f72287661722051387020696e2053396c3870297b6966285138702e6c656e6774683d3d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
