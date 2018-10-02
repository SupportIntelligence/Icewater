
rule k2319_1a109eb9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a109eb9c8800912"
     cluster="k2319.1a109eb9c8800912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['39f74c0d9571cd47f0d3db07b52a1ef51de6c76c','e8b98ca236db05fa1c15fcacbba263ccf3a9a8cd','610f17af19d1870b8e3de4bd183e5206589007fd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a109eb9c8800912"

   strings:
      $hex_string = { 7834442c392e38354532292929627265616b7d3b666f72287661722077395720696e204d384b3957297b6966287739572e6c656e6774683d3d3d28307836443c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
