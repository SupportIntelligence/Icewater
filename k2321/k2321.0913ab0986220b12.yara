
rule k2321_0913ab0986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0913ab0986220b12"
     cluster="k2321.0913ab0986220b12"
     cluster_size="37"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['05408d88c500ae7048c44b3a5ba26fb9','0dcab52a499bbf6e35fb69a518cad035','860c43639bb4a5715abfb33eaef4fbe4']"

   strings:
      $hex_string = { 1164cb9b05f2e2af17e35b3dd8f7aa6beac8fd4d3d3626371f013a03124f417a260d79717cfe1a54909fba58c5451e1b307bd5f66c0ef4e65c628e15342d9802 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
