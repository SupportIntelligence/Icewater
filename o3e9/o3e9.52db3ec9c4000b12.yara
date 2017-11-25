
rule o3e9_52db3ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.52db3ec9c4000b12"
     cluster="o3e9.52db3ec9c4000b12"
     cluster_size="1048"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur ransom"
     md5_hashes="['0011f4c43da665c2a0810b537f3b1150','004c2237b0bcf3eee92e983fcf406ed3','0880eabf1f29d205854ebb478c6744fc']"

   strings:
      $hex_string = { f8d5b3fff5d3b2fff3d0b1fff0ceafffeecbaeffeccaacffebc8abffe8c5a9ffe5c2a8ffe3c0a6ffe2bfa5ffe0bda3ffddbaa2ffdab8a1ffdeae8fc6dfac8514 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
