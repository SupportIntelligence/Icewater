
rule k3e9_293679e351b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.293679e351b2f316"
     cluster="k3e9.293679e351b2f316"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted classic"
     md5_hashes="['156eb5011f4e53a859b29ceee2e93c9f','2ee650235598fbb5271b671d3a8d7361','bb63a64a78f0dffa06d19cd045f5575e']"

   strings:
      $hex_string = { bacb2761552ae12be49e34d7ce84c49d59467e05d662bb9c4425fc91be92fe26f2746e601e2d9faa75331871dde704768c3e865c7b07e2a4082fc2c91aacb33d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
