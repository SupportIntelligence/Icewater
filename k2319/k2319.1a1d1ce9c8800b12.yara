
rule k2319_1a1d1ce9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1d1ce9c8800b12"
     cluster="k2319.1a1d1ce9c8800b12"
     cluster_size="59"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem script"
     md5_hashes="['5ddffc24c63893fc35c97bd128746bbbef0b4018','d9ded88a341fd8f293b06f548a8b3638ac0e2637','59734272cd0abfbaeae369bd7e5e00da668ba592']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1d1ce9c8800b12"

   strings:
      $hex_string = { 2835312c3078323436292929627265616b7d3b7661722069386f3d7b274f3370273a226464222c27493945273a2266222c275730273a66756e6374696f6e287a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
