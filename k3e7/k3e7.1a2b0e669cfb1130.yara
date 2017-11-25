
rule k3e7_1a2b0e669cfb1130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.1a2b0e669cfb1130"
     cluster="k3e7.1a2b0e669cfb1130"
     cluster_size="438"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="smforw smsspy androidos"
     md5_hashes="['000539b33da8d44c5fd78bc570186196','0044bd46cc73f197de87e4670a31451d','078bab08c04507ed18bc53b9a45f7028']"

   strings:
      $hex_string = { 26683c025b1de1030fb3035c5a0113102d1e2d692850030e9b032c6e3c2d1e2d834e030d9a032c6c3c88011914026a4a050da50312ad055ca50110170512060d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
