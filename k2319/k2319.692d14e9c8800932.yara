
rule k2319_692d14e9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.692d14e9c8800932"
     cluster="k2319.692d14e9c8800932"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['50a3dead1f070689e2b7e145a3f4f864ea29cb7f','3d09d6399a5fecf02052e8d65006da59b3cc2d8f','8def30c0353f137e310674be586c044b00357697']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.692d14e9c8800932"

   strings:
      $hex_string = { 773b666f72287661722053355720696e207439643557297b6966285335572e6c656e6774683d3d3d2830783130383e2831362c3132332e293f2837362c38293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
