
rule j2321_24a9e325debb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.24a9e325debb1912"
     cluster="j2321.24a9e325debb1912"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="selfdel generickd upatre"
     md5_hashes="['45bde0152e79f0b800dea7f39812d187','491d2b599d62cad2adbd59fe58436d38','f3928d1e630f91cb0b5acdfbb1d81614']"

   strings:
      $hex_string = { 7e0dbf1e128274973ba65114df636e8d423f0ece4f9a85f5a063a52fa03d7b0b8ed5207fbb6e537250cff3fa4027945ff82b6c46f99103fb6f47b9ef35d1d461 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
