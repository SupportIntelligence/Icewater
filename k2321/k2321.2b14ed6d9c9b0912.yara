
rule k2321_2b14ed6d9c9b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b14ed6d9c9b0912"
     cluster="k2321.2b14ed6d9c9b0912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['1cb87d873c2299d0b7edc0ceaab571f0','2e0d35e74afcb3a895ccf78123e439ed','ef320e7388b4812077aaf7049871716f']"

   strings:
      $hex_string = { be674f4971f1a0e464c43c018bc563f8410290c080ce0aa150cce54af97c70259ad4373d87a6a48c1e3972dcd8317f8e879faf0f9bc9848320530de89198337e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
