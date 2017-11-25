
rule n3e9_1bcac4cfee630b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bcac4cfee630b16"
     cluster="n3e9.1bcac4cfee630b16"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['10fc04b404c125ce5fc6f4244ae86cab','33e9513d9d6760fcc02642d6857666a3','a23bf3ba8333f8c9c1014444f331fabb']"

   strings:
      $hex_string = { 006c006f00770020006400750070006c00690063006100740065007300200028002400300025007800290023004100200063006f006d0070006f006e0065006e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
