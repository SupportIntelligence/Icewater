
rule j2319_4a249a912d2d48ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.4a249a912d2d48ba"
     cluster="j2319.4a249a912d2d48ba"
     cluster_size="7"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cryxos html expkit"
     md5_hashes="['12114a6fd3ad24a225a29eab244a38e0','2347dd1b2eb49f7d1122cf52f243e96e','ffcd402900a351cb8ab14ff28f271c1e']"

   strings:
      $hex_string = { 6578742f6a617661736372697074223e0d0a3c212d2d0d0a646f63756d656e742e777269746528756e6573636170652827253363253634253639253736253230 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
