
rule k3e9_2b6d5252529348ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b6d5252529348ba"
     cluster="k3e9.2b6d5252529348ba"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy flmp"
     md5_hashes="['0b3a93287444197e3fee7d9a8f0c0328','26860d1b1e56dc1659233a32a50b9a58','bde785809ea40525df497d843b1e355c']"

   strings:
      $hex_string = { 952039c704370f66075ac44cbbdee80bd39d0994db5178fe27e6e556533d1f625e6716732b43c8b270add88df61381c57d42925582ed21b097d759a50da3d98f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
