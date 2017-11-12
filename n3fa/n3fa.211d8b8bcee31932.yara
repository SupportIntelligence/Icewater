
rule n3fa_211d8b8bcee31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fa.211d8b8bcee31932"
     cluster="n3fa.211d8b8bcee31932"
     cluster_size="6261"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="snare snarasite adsnare"
     md5_hashes="['000302cbd5bac128d6446984c2c507b4','00086883f12db4591ed740caecae8b2e','00b981235eacfb285da13e895f5c99d1']"

   strings:
      $hex_string = { 2b92fef155e6034c88143836e7a0c3b739b8bd133fffaa9c8603787f9c3c413c64c66dc7ace7262dc9a5e148fb7989dcc01d88b9bbc6a75177acf956c5f6608e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
