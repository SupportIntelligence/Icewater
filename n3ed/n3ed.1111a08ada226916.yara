
rule n3ed_1111a08ada226916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1111a08ada226916"
     cluster="n3ed.1111a08ada226916"
     cluster_size="66"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi delf atraps"
     md5_hashes="['00d93e4f622f253a4871c55d17fd8e7e','0c59bb884eca203fac8ff21afbb9bb1e','982df60dc6b996a5385c77333be87ec2']"

   strings:
      $hex_string = { ecb3c39ed17c5348f646badff840abd022fa6ca6097e343e01d7cd915690262d5e5bdc6f8f55e124d91ee3ad7f8ed388bc838414e7d6a94200fd71b172cea864 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
