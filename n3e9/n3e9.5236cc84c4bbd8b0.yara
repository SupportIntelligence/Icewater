
rule n3e9_5236cc84c4bbd8b0
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5236cc84c4bbd8b0"
     cluster="n3e9.5236cc84c4bbd8b0"
     cluster_size="9243"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['00146a77431ed7a295d4afe72de06faa','00224858620377b734fc016200467dfa','00d5d9ac1b9e970ec87ffb1e60a44eeb']"

   strings:
      $hex_string = { 000102030405060708171e23272b2e313437393c3e40424446484a4c4e505153555658595b5c5e5f616263656667696a6b6c6e6f7071727375767778797a7b7c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
