
rule n231d_7b1d6b49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.7b1d6b49c0000932"
     cluster="n231d.7b1d6b49c0000932"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddenapp riskware androidos"
     md5_hashes="['3c46eda54ef4b08e69db1f53675653291fb64232','d68f25a2468f2e63dbf7611d61bd6290ff2f073f','9c14d938cfeb36d533296c0a3d513bbbe7d58902']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.7b1d6b49c0000932"

   strings:
      $hex_string = { 7d041ad1a3487533bbe7bdc8cd0129d73e1d00729a28071039738514c409387fae8bba6bb83a7a578e4240e1cf081be490eb6615596e2f377045fd76deca9697 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
