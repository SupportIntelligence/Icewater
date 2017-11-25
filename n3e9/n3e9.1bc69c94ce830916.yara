
rule n3e9_1bc69c94ce830916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc69c94ce830916"
     cluster="n3e9.1bc69c94ce830916"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious ageneric"
     md5_hashes="['263e6686ea0febf3e997e304a4f649d4','630b5060246f9391ea617a89c6e93564','d1227735035ada0be40e2d9feadc8f35']"

   strings:
      $hex_string = { 006c006f00770020006400750070006c00690063006100740065007300200028002400300025007800290023004100200063006f006d0070006f006e0065006e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
