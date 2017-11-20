
rule i3ec_04b48b2cc36b1bb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ec.04b48b2cc36b1bb2"
     cluster="i3ec.04b48b2cc36b1bb2"
     cluster_size="10"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['4aeff79deeab7108886a78e0a60cc525','546218c3611a4db6bb3f34f18549a3b6','ea137229eb3804ff2f7680a861dda56d']"

   strings:
      $hex_string = { b4658715d9a1333b14b3c363d9616c6a329bea86caeb31d067ab2f1f9d6d4e979c6a9ada98b79fdab87443e5fd897796a4d7555fee3871f4c78d69cbe4b5531b }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
