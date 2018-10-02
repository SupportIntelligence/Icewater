
rule k2319_692d1ae9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.692d1ae9c8800932"
     cluster="k2319.692d1ae9c8800932"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['bf6f7e02cd62267d974d6e8e261b9cf9cf84bbbc','3398059cfb29b2163d85c6d45b18df8d6b1aed78','4126ec9763d1ff120a54bfa676823dccb9a0acf7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.692d1ae9c8800932"

   strings:
      $hex_string = { 773b666f72287661722053355720696e207439643557297b6966285335572e6c656e6774683d3d3d2830783130383e2831362c3132332e293f2837362c38293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
