
rule n231d_3b166a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.3b166a49c0000b12"
     cluster="n231d.3b166a49c0000b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddenapp riskware androidos"
     md5_hashes="['45c7d9c3b21e0cb72e417837a7f60c013b331994','c1ea40ded8f800564a0734226b78ea1cd29e2c8b','5366afa32cad5ef9b53d585eba8405a1f68c2d73']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.3b166a49c0000b12"

   strings:
      $hex_string = { 7d041ad1a3487533bbe7bdc8cd0129d73e1d00729a28071039738514c409387fae8bba6bb83a7a578e4240e1cf081be490eb6615596e2f377045fd76deca9697 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
