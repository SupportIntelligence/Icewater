
rule n3ed_5a1b94d3dba30b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5a1b94d3dba30b16"
     cluster="n3ed.5a1b94d3dba30b16"
     cluster_size="79"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['00697d866b24f3d65206f24fd1d8a1e7','00e3d407c38ee11405fbfca717d2266a','0e7af2a607ea10ff099b8fe1640592d6']"

   strings:
      $hex_string = { 780102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
