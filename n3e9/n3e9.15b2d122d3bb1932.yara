
rule n3e9_15b2d122d3bb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.15b2d122d3bb1932"
     cluster="n3e9.15b2d122d3bb1932"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['3dc04f702f8d36560cf42ea510516a0a','6aedf917d94a9b82ae597e51895d9d8b','d6daf708a35ce4123b06952b33b4047e']"

   strings:
      $hex_string = { 6f00770020006400750070006c00690063006100740065007300200028002400300025007800290023004100200063006f006d0070006f006e0065006e007400 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
