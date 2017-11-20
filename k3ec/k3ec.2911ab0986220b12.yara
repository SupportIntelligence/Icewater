
rule k3ec_2911ab0986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.2911ab0986220b12"
     cluster="k3ec.2911ab0986220b12"
     cluster_size="11"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['1f89c33e22ad441d4d921b31e5fb39ef','26562497f4b7fb9aeebe8540ee6b13bd','cd3c4e0cdc9294debb638b152d11c0e2']"

   strings:
      $hex_string = { 1164cb9b05f2e2af17e35b3dd8f7aa6beac8fd4d3d3626371f013a03124f417a260d79717cfe1a54909fba58c5451e1b307bd5f66c0ef4e65c628e15342d9802 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
