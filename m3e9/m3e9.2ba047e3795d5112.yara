
rule m3e9_2ba047e3795d5112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2ba047e3795d5112"
     cluster="m3e9.2ba047e3795d5112"
     cluster_size="338"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="techsnab getprivate nsis"
     md5_hashes="['00d81e818b7e2df906407a4250f958e7','00f04635fc9e7e0c97e64ac70c50952c','0ed289d1b3bef3f30a3a0ff2d994ec07']"

   strings:
      $hex_string = { 26a05c2b48d6ed2261f34ff4bd65f2d78a85d05b15e68e5f49f83f781a5a62886a73d46602a4cf0568364c818ceb4a97c1710da8aea591dc01132eafa97774be }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
