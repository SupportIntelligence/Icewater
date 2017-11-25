
rule j3f7_4a249a912d2d48ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.4a249a912d2d48ba"
     cluster="j3f7.4a249a912d2d48ba"
     cluster_size="14"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cryxos html expkit"
     md5_hashes="['012940b15807b10ecb93a6b335f37ed0','1f519442b7bd5da4b42618c7169cfd76','fb1186694f67e8e90b48ffaf4fc539c7']"

   strings:
      $hex_string = { 6578742f6a617661736372697074223e0d0a3c212d2d0d0a646f63756d656e742e777269746528756e6573636170652827253363253634253639253736253230 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
