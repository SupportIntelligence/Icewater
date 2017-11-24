
rule k2319_119c9499c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.119c9499c6220b12"
     cluster="k2319.119c9499c6220b12"
     cluster_size="11"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery classic eiframetrojanjquery"
     md5_hashes="['3643ee7157f69342c668505836d2d15b','4f394fa4e4becf195515c2bcdedb96d7','f3820661b0f767838af142c0bc495ebc']"

   strings:
      $hex_string = { 6d6528292b36302a632a36302a316533293b76617220653d22657870697265733d222b642e746f555443537472696e6728293b646f63756d656e742e636f6f6b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
