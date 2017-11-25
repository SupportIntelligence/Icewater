
rule m2321_5aa14c423543485a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.5aa14c423543485a"
     cluster="m2321.5aa14c423543485a"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['791f1eb6ed3437e8393bc983e57a41de','bb30d581a95e040b40882349a748bb1d','ea0d0c883f9ed6c9b5d9bfdced897717']"

   strings:
      $hex_string = { 7ef61c42b4833eb9e9c9fa88d8f0188185b80dc3ae7c2d463dc2a25280704466eca901c1fd4c515bbc28a6a8e19c82bef3e8bf004ab6a0981d2cc00e32a5f793 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
