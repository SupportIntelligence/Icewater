
rule m3e9_391c3ac1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.391c3ac1cc000b16"
     cluster="m3e9.391c3ac1cc000b16"
     cluster_size="76"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi buzus gamarue"
     md5_hashes="['0163b7205056dfbf40506732c66fe870','029abca0fe35e5131a503568c84068e4','441fc1dfc0516ef29305fbd4b90e3ba0']"

   strings:
      $hex_string = { d43689f38c0e0f3295ae546f63cd04b0a2e8fabd263c463a4790ec92496e3ba1184f17ba938eff0c9177e3c3d2e541e2378d22ef6168c0c219a61eaad5c5796d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
