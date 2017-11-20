
rule i2321_04b48b2cc36b0b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.04b48b2cc36b0b30"
     cluster="i2321.04b48b2cc36b0b30"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['5baa3fdddaacad6714744058e74e0796','6da3b1cc4914f5575858af1cf696f9b6','fbb4f4e9fd4a88641f2dee99f7e8b955']"

   strings:
      $hex_string = { b4658715d9a1333b14b3c363d9616c6a329bea86caeb31d067ab2f1f9d6d4e979c6a9ada98b79fdab87443e5fd897796a4d7555fee3871f4c78d69cbe4b5531b }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
