
rule m3ed_531403b999446912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.531403b999446912"
     cluster="m3ed.531403b999446912"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['3f8d803ce475f5229f58ae8a5a8ff6f7','726ef40fb300d2b8688d5ed4ff641b0e','df2050133e260a53634c213b4de14800']"

   strings:
      $hex_string = { 325d33ce338b351f36ec364337553722382a39763ae63a1d3b353b593c913c5f3dd73d063e3d3e4d3e893ef93e0000010048000000ab309a31d5323b34c634b8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
