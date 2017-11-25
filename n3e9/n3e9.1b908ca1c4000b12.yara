
rule n3e9_1b908ca1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b908ca1c4000b12"
     cluster="n3e9.1b908ca1c4000b12"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi small rodecap"
     md5_hashes="['ac31f44d5bebb763ddf92492ae4d5bd0','ad95b09fbd105f6f84cbd87942d3b97d','b45f7c4c58b4d4885f4d6effbfffc60f']"

   strings:
      $hex_string = { f47cd08bf06a02c1e6028d4de85a2bce3bd07c088b31897495e0eb05836495e0004a83e90485d27de733c05e6a1f592b0dcc134600d3e38b4decf7d91bc981e1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
