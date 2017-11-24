
rule k2321_0b324a69d5bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0b324a69d5bb0912"
     cluster="k2321.0b324a69d5bb0912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ganelp autorun emailworm"
     md5_hashes="['5793019b3cf0c0b77d0ea167762c6cf8','9e571cc4a58b89efcc290753ae436a24','ef2a8ceb1f9f84ab63043944f95632b3']"

   strings:
      $hex_string = { 5a6a2d7e543c26752fd41fb9530966a360369418f2f1d88cc530445e76553ba848e4a94c80bc9768d2216b05bda631cde295f76395f5423f1d6db59272da8041 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
