
rule n3e9_2b54ca98c2210b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b54ca98c2210b36"
     cluster="n3e9.2b54ca98c2210b36"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi dealply malicious"
     md5_hashes="['1b87a00c795287ea01fb52b689490c8f','2df3a92316698480612e6e72d355f35b','bffb5fa60b5fa6193b4776994ad34ee6']"

   strings:
      $hex_string = { 006e000e0053007400610063006b0020006f0076006500720066006c006f0077000d0043006f006e00740072006f006c002d0043002000680069007400160050 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
