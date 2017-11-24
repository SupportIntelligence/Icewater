
rule m2321_2332a434dec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2332a434dec30912"
     cluster="m2321.2332a434dec30912"
     cluster_size="339"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi download heuristic"
     md5_hashes="['0082fc5828adef6a0964f496e797d693','0086f3dffef1c4d73c6652f0e1f93bdc','068c9bc176d5ad13b7641812fb79f3ef']"

   strings:
      $hex_string = { 2dc2882793b846cebc60a13015b06f129c2090d5efca1a0a8d98863e62fb637933fb52bed1f9f197877525b2f25e76f719b1290bbd9de6eb711c5c3d34e874d9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
