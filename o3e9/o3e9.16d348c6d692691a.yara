
rule o3e9_16d348c6d692691a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.16d348c6d692691a"
     cluster="o3e9.16d348c6d692691a"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster bundler installmonstr"
     md5_hashes="['02a604cb0416e00e17f2c3bf1a45c32d','25e7fd236bc0b409505a0c0cd2a55f49','b52316357731bfadab4cf20002652b80']"

   strings:
      $hex_string = { 6c01e21d7189394473838f21eb94e6d7bfdd14d47ae033c8568b1807931cabe8593bcafbd0f3c5fdf5350e5eb5aadbbecc74f1d105ff2896cb1fd212856a7654 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
