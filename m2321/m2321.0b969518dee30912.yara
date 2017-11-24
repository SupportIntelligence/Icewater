
rule m2321_0b969518dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b969518dee30912"
     cluster="m2321.0b969518dee30912"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['10af37a3fc4d93bca1666b175ca62dd1','17c6c367892b4f6efb5da0d4b70f2b6e','d11c5b29f61960360c308cde7849fd1c']"

   strings:
      $hex_string = { ee2d2ec8bd0585d937ed0177574fdd3a186c545f4def8ae2cbf6e9420cb6d15d66767ce01d4bf822bc67215aba4170d38ec0eb0b2c6fb990c34586c250680d56 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
