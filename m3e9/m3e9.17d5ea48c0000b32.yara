
rule m3e9_17d5ea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.17d5ea48c0000b32"
     cluster="m3e9.17d5ea48c0000b32"
     cluster_size="79"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['037bab49580974317257d4c58ea60c0f','09be5f9bc8a27e245a52f7e450fe996e','3b0ae6e20facfc3c9e0b112e3a45925f']"

   strings:
      $hex_string = { cc6a0c68e07f0001e81bf9ffff33c08b4d0885c9744483f9ff743f2145fcba4d5a0000663911752b8b513c85d27c2481fa00000010731c8d040a8945e4813850 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
