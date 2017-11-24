
rule m3e9_292451d4ea210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.292451d4ea210932"
     cluster="m3e9.292451d4ea210932"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys malicious"
     md5_hashes="['a76978d2c8f79b4a35c69cd5ac47d03e','be20c8e8c691dcfa187a1094acd4731f','f591b98276217be29619fcaeb8697cd5']"

   strings:
      $hex_string = { 151f272953595a5a617b89894f4b62958e94a1a3a3a2b6c8d7e9f0fffffffffcfbf5b1000000f6ffff02101e121c1d1c204d546061767a80a9c5d2ccbebfc1ce }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
