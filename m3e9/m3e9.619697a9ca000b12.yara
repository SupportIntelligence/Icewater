
rule m3e9_619697a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.619697a9ca000b12"
     cluster="m3e9.619697a9ca000b12"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['063d9643677d7c8d13295b1ad659b3c1','5f7f75773a5a779f95373d2fa566553c','d0750fb4bec2f90bf1bdddeb28d5de6f']"

   strings:
      $hex_string = { d3eec8d43db62622e640a2aafdd6d97e5ff93ef41d0f52dd773efbac362abfb14f20f0430dc99156199f5df2d742c40e4e2eea063a00be72012d73aff71a68ad }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
