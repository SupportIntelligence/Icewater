
rule n3e9_1bc6949dc6210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc6949dc6210b32"
     cluster="n3e9.1bc6949dc6210b32"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious banker"
     md5_hashes="['2d5f628a0bd3f1960e3fb404354346e7','52f7ef20361916d107fd6a85dc042fff','f8306e54af654b3744687c2c34d2b76e']"

   strings:
      $hex_string = { 006c006f00770020006400750070006c00690063006100740065007300200028002400300025007800290023004100200063006f006d0070006f006e0065006e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
