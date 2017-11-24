
rule m3e9_0a4344463143485a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0a4344463143485a"
     cluster="m3e9.0a4344463143485a"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['76d0a06ac1c5146c72d534ec3e969a63','7bf8139b7b2144714a8398779b6fc72b','fa371eef49dfcc7ce92afbd319fd2482']"

   strings:
      $hex_string = { 7ef61c42b4833eb9e9c9fa88d8f0188185b80dc3ae7c2d463dc2a25280704466eca901c1fd4c515bbc28a6a8e19c82bef3e8bf004ab6a0981d2cc00e32a5f793 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
