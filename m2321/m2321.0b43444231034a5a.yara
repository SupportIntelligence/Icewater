
rule m2321_0b43444231034a5a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b43444231034a5a"
     cluster="m2321.0b43444231034a5a"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['023b45483c6b4d455cb26f2846c76fd5','4622b1f46682e2f788d83402953c103d','ed84307defe14c9b8227a4235baf3acc']"

   strings:
      $hex_string = { 7ef61c42b4833eb9e9c9fa88d8f0188185b80dc3ae7c2d463dc2a25280704466eca901c1fd4c515bbc28a6a8e19c82bef3e8bf004ab6a0981d2cc00e32a5f793 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
