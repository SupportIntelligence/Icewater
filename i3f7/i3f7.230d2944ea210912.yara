
rule i3f7_230d2944ea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3f7.230d2944ea210912"
     cluster="i3f7.230d2944ea210912"
     cluster_size="67"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html phishing phish"
     md5_hashes="['00a1b633385585fc96e3487813b7517f','01ade671a1c59838c415d75838496b5e','3971be1d0f00437283a31d61a0933e4c']"

   strings:
      $hex_string = { 636861727365743d77696e646f77732d31323532223e0d0a3c7469746c653e457863656c204f6e6c696e65202d2030394b534a444a52343834333938344e4639 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
