
rule k2321_2a6d5252529348ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2a6d5252529348ba"
     cluster="k2321.2a6d5252529348ba"
     cluster_size="26"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy flmp"
     md5_hashes="['0736e43a5a8300832971351ddb11b3f6','12893df677a006c892e3f958de3286c2','8632b29ac0b31a422c1ab679693e93e5']"

   strings:
      $hex_string = { 952039c704370f66075ac44cbbdee80bd39d0994db5178fe27e6e556533d1f625e6716732b43c8b270add88df61381c57d42925582ed21b097d759a50da3d98f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
