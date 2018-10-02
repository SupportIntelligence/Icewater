
rule k2319_311596b9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.311596b9c8800932"
     cluster="k2319.311596b9c8800932"
     cluster_size="43"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['f51aca41e5467386a033d76427e2b228094255d0','8ce2c840376aae9193b3aa15a5c2cb93e6738c66','2491bdcd1cec6ad9ef52f11224491871ae4b8871']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.311596b9c8800932"

   strings:
      $hex_string = { 333f2834302e3545312c313139293a2830783145442c31342e30384532292929627265616b7d3b76617220433949373d7b276830273a66756e6374696f6e2864 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
