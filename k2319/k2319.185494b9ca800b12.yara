
rule k2319_185494b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185494b9ca800b12"
     cluster="k2319.185494b9ca800b12"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['024aa89379e0a2dc35e17a9e9e4d5e00dab2dcb5','a63adbd34d5a2af03e52375028f9d3b472983769','ce313161f8f9b72346574e993233342c44961786']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185494b9ca800b12"

   strings:
      $hex_string = { 39392c313030293a28307845462c31362e292929627265616b7d3b666f7228766172204b335520696e2075334d3355297b6966284b33552e6c656e6774683d3d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
