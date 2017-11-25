
rule n3e9_251d3cc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.251d3cc1cc000b32"
     cluster="n3e9.251d3cc1cc000b32"
     cluster_size="453"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['0011a112ec86038aca013c29b5d9038b','0013bc36b42530b6e83fc01c803dd127','0dc0530e5dd8d4b463fe516f988c48b8']"

   strings:
      $hex_string = { 68ae36822a62b6949289b95dab5609b0c01d12214ffc1b9d0d0aaf0e0820dd2d3c9a26751519e8b7556fbedb9bebc98fb5aa4ee60160764b1c47d1f278e7e141 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
