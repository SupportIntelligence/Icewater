
rule i3ec_04b48b2cc3694b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ec.04b48b2cc3694b32"
     cluster="i3ec.04b48b2cc3694b32"
     cluster_size="7"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['3602a2f21ccba05c28392d070b04fcce','6795e6e250c8c46d4aac596627efebcf','df9cb13b43ecc7c6efc125307dff9a98']"

   strings:
      $hex_string = { af3f4ab29a2ca22ddfb97afcaeb9397efde68bf7e49fe2de75c6ff088f5c5276ddadf3ff33fd723c5b1f36f7f60da65da3e5eec1913dc3a5071e1f2af5a7c9b1 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
