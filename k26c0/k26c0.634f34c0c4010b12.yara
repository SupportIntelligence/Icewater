
rule k26c0_634f34c0c4010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c0.634f34c0c4010b12"
     cluster="k26c0.634f34c0c4010b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeav malicious click"
     md5_hashes="['ffbe6bcbf17c30b6373e4fa1c445553f32a9f729','722ee96708b9aff04121ae83d57b44e1d7114bcb','a14767d2c1e8203eee0f6b5849b43d25374bc8dd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c0.634f34c0c4010b12"

   strings:
      $hex_string = { 4f7574707574417474726962757465002505577269746546696c65004b45524e454c33322e646c6c00000e024d657373616765426f7841005553455233322e64 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
