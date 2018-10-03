
rule n231b_6994d6c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231b.6994d6c9c8000b12"
     cluster="n231b.6994d6c9c8000b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['c2b50873dc9607095b7a28d7682026dd39390199','d2d1f0e53d22865066ebe2bbb7d1f3d43c8c1efd','935b1a605ec21e12060066560f7b920849863c60']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231b.6994d6c9c8000b12"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
