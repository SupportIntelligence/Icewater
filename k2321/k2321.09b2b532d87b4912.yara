
rule k2321_09b2b532d87b4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09b2b532d87b4912"
     cluster="k2321.09b2b532d87b4912"
     cluster_size="43"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['0222c7269a1e8ce86757ff619b9bcdd0','0a3b0ba788e2807c45813ba46a75a00d','6a337f91f49ff044bafcdaac4ab7d35b']"

   strings:
      $hex_string = { ee0d1895097d9edc60a6323de8d80c7d9015814076fef619c60a02b0a439369030a589cb1dba207c94210f0ea2aec2888ee17416558667a8a0ea48a3d41bd042 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
