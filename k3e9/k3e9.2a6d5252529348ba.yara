
rule k3e9_2a6d5252529348ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2a6d5252529348ba"
     cluster="k3e9.2a6d5252529348ba"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy flmp"
     md5_hashes="['12a2d80406697e557dd5f8c43f9c9a9e','370a520ad0e3457a54d4be980a1b662a','c78b6d490741bbe461ee0ea7a0f95d5e']"

   strings:
      $hex_string = { 952039c704370f66075ac44cbbdee80bd39d0994db5178fe27e6e556533d1f625e6716732b43c8b270add88df61381c57d42925582ed21b097d759a50da3d98f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
