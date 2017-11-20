
rule i2321_06b48b2cc36b1b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.06b48b2cc36b1b36"
     cluster="i2321.06b48b2cc36b1b36"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['056270b99161508b1f8e7a4215847b27','23a45fa5d69ed318b1e57e9614d766cc','f1169d08bb9fc842305f15dabfeca722']"

   strings:
      $hex_string = { b4658715d9a1333b14b3c363d9616c6a329bea86caeb31d067ab2f1f9d6d4e979c6a9ada98b79fdab87443e5fd897796a4d7555fee3871f4c78d69cbe4b5531b }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
