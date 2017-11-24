
rule k2321_29359422ddb39932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29359422ddb39932"
     cluster="k2321.29359422ddb39932"
     cluster_size="42"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installm unwanted downware"
     md5_hashes="['050a7080e45d6f1ba6a1bc4b41825fb8','08b8b12d398061393a200828ce5f95d3','4fe35ee76f0fe0368813b7eae32d6557']"

   strings:
      $hex_string = { 4706040c0b991ce91b3983d9c4b51eeee7e4ef1f19101505764a6b58b8afbf3a5f1403edccc1326ee1feb2d00017df307f4adb384c13c584480786fb63c77eb4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
