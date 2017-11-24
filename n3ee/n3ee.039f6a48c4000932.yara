
rule n3ee_039f6a48c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ee.039f6a48c4000932"
     cluster="n3ee.039f6a48c4000932"
     cluster_size="83"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['00def032ccc6a47ffdb39d4b0cb824d4','012669e85679bdec44d63adc4b031eeb','0fa99d987865babbd666d13a240847c0']"

   strings:
      $hex_string = { 048a582d881c0e66ff400c8b70306a10592bced3fa8d4c3ef05b6689502ceb08d3e26609502c03cf8948305ec38bff558bec33c00fb64d08d17d0883e1010bc1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
