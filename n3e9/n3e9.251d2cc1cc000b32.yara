
rule n3e9_251d2cc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.251d2cc1cc000b32"
     cluster="n3e9.251d2cc1cc000b32"
     cluster_size="594"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['00a253c31e1263e645b1827d87b77d53','028bbb0f1febd510a7e5e369fa5a62b1','16d9fc8003376d3112a9b24527f3f13d']"

   strings:
      $hex_string = { 016b4db416e2a6732260c2f762ab59db7f18e698c7e615818375aa594648c3dfc5e1731c20ae103f11391f39c078470d9f7520b7d30fb5bf1b9efa162459cb36 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
