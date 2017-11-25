
rule n3e9_1bcac44f6e210b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bcac44f6e210b16"
     cluster="n3e9.1bcac44f6e210b16"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious adwaredealply"
     md5_hashes="['0125a58687010404a784efe3ac82b753','2f09b3eed9bfdb3c9c761dbda3fb0753','da1bf3e6c30875d691470cb00449f6d0']"

   strings:
      $hex_string = { 006f00770020006400750070006c00690063006100740065007300200028002400300025007800290023004100200063006f006d0070006f006e0065006e0074 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
