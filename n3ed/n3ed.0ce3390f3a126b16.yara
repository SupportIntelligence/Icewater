
rule n3ed_0ce3390f3a126b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ce3390f3a126b16"
     cluster="n3ed.0ce3390f3a126b16"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['27e8a03e4d6aaa3dbc360b8353e37771','917d838be115a34a77af78402ee794a4','dff83753889894263ee512af26db3c8d']"

   strings:
      $hex_string = { 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
