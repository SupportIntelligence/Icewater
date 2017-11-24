
rule n3e9_258533e1ca000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.258533e1ca000932"
     cluster="n3e9.258533e1ca000932"
     cluster_size="74"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['0759f25a8aefe5439793b3f602130320','3f4c3f29d5f079a8ff1fcdcda97d5f3f','ad926361318d24ae8fb68ae892d0abac']"

   strings:
      $hex_string = { 27d05a0e88441e2e58110c3cf06ef80721897414992995923e9ec4cb71137c553a4dc17a7b43efa42cfb85b2ff9cdc250aceeb676172bb343728c8ca97df6bde }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
