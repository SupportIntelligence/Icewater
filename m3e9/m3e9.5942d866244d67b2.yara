
rule m3e9_5942d866244d67b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5942d866244d67b2"
     cluster="m3e9.5942d866244d67b2"
     cluster_size="48"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbinject autorun"
     md5_hashes="['0a5e585b30a970ec6bf1c8da90122a74','26a87bfbae4f2bc036caf71e1ab1289b','ba5e3500252e54aaffc0115b6006f47d']"

   strings:
      $hex_string = { 8500fbefb4fe603174ff360c003cff1cff04fff4fed4feb4fe00101bd2021bd3022a463cfffcf6a4fe00276c74fff4052b18fff4022b1aff0b84000800e759a0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
