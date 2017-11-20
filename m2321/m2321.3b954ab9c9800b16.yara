
rule m2321_3b954ab9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b954ab9c9800b16"
     cluster="m2321.3b954ab9c9800b16"
     cluster_size="430"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['015d4df80d149aae8866be79c732f53c','0380f65739879124fdb5a7eadbe0b3d1','0b80bd7d249a805adce9ffa06fb5257c']"

   strings:
      $hex_string = { aa254be10b0d67cf5eb97cf9f7df7fd7f2a45c799ebfffded2dcf4c18e1d6b56ad9a969b3b28265a15120cb6e8a804a1f754ca44c4618fd010081a953e6c4e75 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
