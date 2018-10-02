
rule k2319_185496b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185496b9c2200b12"
     cluster="k2319.185496b9c2200b12"
     cluster_size="53"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['39f407697858720015f62f99660525a645078112','198f434dbfd7cd7e641a95cba1004ad2c8a588f5','9085253ea5c17180004083d65745cf746a07e355']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185496b9c2200b12"

   strings:
      $hex_string = { 39392c313030293a28307845462c31362e292929627265616b7d3b666f7228766172204b335520696e2075334d3355297b6966284b33552e6c656e6774683d3d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
