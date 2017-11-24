
rule n3e9_4c9f94c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4c9f94c9cc000b32"
     cluster="n3e9.4c9f94c9cc000b32"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['1f627379a1e73be4080577c7eb4d0f17','90ddd75bd6af71a157a8783e8d432433','c0ab654955a863185321739fd08c3fe7']"

   strings:
      $hex_string = { 27d05a0e88441e2e58110c3cf06ef80721897414992995923e9ec4cb71137c553a4dc17a7b43efa42cfb85b2ff9cdc250aceeb676172bb343728c8ca97df6bde }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
