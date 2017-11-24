
rule k3f7_111b14b9c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.111b14b9c2200b32"
     cluster="k3f7.111b14b9c2200b32"
     cluster_size="23"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery classic eiframetrojanjquery"
     md5_hashes="['1410ef8ca6258a70cc2841ed84b453ff','2c554db48376172209db24d4b2b68069','be61bea86eab951c635dc10bfa675ca5']"

   strings:
      $hex_string = { 6d6528292b36302a632a36302a316533293b76617220653d22657870697265733d222b642e746f555443537472696e6728293b646f63756d656e742e636f6f6b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
