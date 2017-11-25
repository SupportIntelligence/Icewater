
rule n3e9_1bcac48dee210b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bcac48dee210b16"
     cluster="n3e9.1bcac48dee210b16"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious cloud"
     md5_hashes="['16dc6c39d58a077aef09f96b0745a31f','1f5ac049c0b3ab7995345a9040d238f1','b3409fd29d892c71896e0044a25a3536']"

   strings:
      $hex_string = { 006c006f00770020006400750070006c00690063006100740065007300200028002400300025007800290023004100200063006f006d0070006f006e0065006e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
