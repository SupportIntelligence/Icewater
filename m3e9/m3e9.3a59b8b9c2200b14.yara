
rule m3e9_3a59b8b9c2200b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a59b8b9c2200b14"
     cluster="m3e9.3a59b8b9c2200b14"
     cluster_size="40"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['06ed74d16b31207a322389e0ddc58591','08f8ab0de44d09b14ee90c10ca0aa417','686916a4d22b4d68b1cb25e9d6fc0013']"

   strings:
      $hex_string = { d1474249ca32384f66309a039fda75634a489b4cf1ddc5aa1798eddbb60dcbd9f6e61cb876c9a389ab092288e1c8eb3139b30762e98607185b964db77774af46 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
