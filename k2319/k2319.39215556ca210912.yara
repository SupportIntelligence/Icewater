
rule k2319_39215556ca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39215556ca210912"
     cluster="k2319.39215556ca210912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik script"
     md5_hashes="['331164041b56ddf5519f54d5272f89e274f7fb56','21b674e05d14d09dc34a835bdc0366fb233a4876','19499586d7625b50e9ff55bb284f84ed22925730']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39215556ca210912"

   strings:
      $hex_string = { 616b7d3b666f7228766172204c337520696e204e31473375297b6966284c33752e6c656e6774683d3d3d282837372c3838293c392e303945323f283078313543 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
