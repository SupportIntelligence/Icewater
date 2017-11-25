
rule o3ed_131a9d99cee30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.131a9d99cee30916"
     cluster="o3ed.131a9d99cee30916"
     cluster_size="1154"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['00de1aba083f34e4eaa5b7a8a4b8548f','015871d3fc6a3235b6344fcd9661b3f0','09dd10fe01097bd639dcfe8172654116']"

   strings:
      $hex_string = { ca0fbfc92bcb03f14050ff1590811708598945e483fe097e126a095e8d443de8803c303075054e85f67ff52b75e4790433c0eb028bc68b4dfc5f5e33cd5be85a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
