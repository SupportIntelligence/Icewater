
rule n26bb_1b128908d912f112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1b128908d912f112"
     cluster="n26bb.1b128908d912f112"
     cluster_size="1545"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ymgfawizrvpi malicious attribute"
     md5_hashes="['d16df02913afcc8468d2e9c98344ec6347502718','fb381a4f5163ffe1b67a607ad2c481814e4f19d1','303531153038cda4e3ec90b1124c9ce140f08d54']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1b128908d912f112"

   strings:
      $hex_string = { f3afe65f22bd123cb56e0a6379aaecb6596f1c154cd203bfe2556dfb6a8d3852043fcd494e871074195c66e7e56c39334a96da110184f478052dcf363581dcdd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
