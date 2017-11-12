
rule m3ed_531403b999246916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.531403b999246916"
     cluster="m3ed.531403b999246916"
     cluster_size="100"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['058b42f501593f2e98ae8cc9b6489106','0a1e067e4304ec9e657a8e199711d145','6814b7e84cf3a3634e0bed731d7f82b8']"

   strings:
      $hex_string = { 88325d33ce338b351f36ec364337553722382a39763ae63a1d3b353b593c913c5f3dd73d063e3d3e4d3e893ef93e0000010048000000ab309a31d5323b34c634 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
