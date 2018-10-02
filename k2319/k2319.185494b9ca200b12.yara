
rule k2319_185494b9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185494b9ca200b12"
     cluster="k2319.185494b9ca200b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['25bbb81c1618fc3e0c53c772c677803cc6855ed7','ee8e282f8f83e03a9aa42c2a79fcb3a2c33a6a8e','349e495480619a87532a38004c9699c132f7cf65']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185494b9ca200b12"

   strings:
      $hex_string = { 39392c313030293a28307845462c31362e292929627265616b7d3b666f7228766172204b335520696e2075334d3355297b6966284b33552e6c656e6774683d3d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
