
rule i445_09914928c0000b22
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.09914928c0000b22"
     cluster="i445.09914928c0000b22"
     cluster_size="4"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jenxcus dinihou autorun"
     md5_hashes="['33998718c3e4be1a69c78725713cf8d4','adf6d5f5c5293e75b06736b71ec6d1c1','e20bb89d5c3d04f2d0b749f57069d454']"

   strings:
      $hex_string = { 6400690063006f006e002e0065007800650014030000070000a02553797374656d526f6f74255c496e7374616c6c65725c7b39303134303030302d303031312d }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
