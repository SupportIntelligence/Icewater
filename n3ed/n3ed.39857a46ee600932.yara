
rule n3ed_39857a46ee600932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39857a46ee600932"
     cluster="n3ed.39857a46ee600932"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['1e583f4056a3f29f0e8be2be0ffb6850','c0b92e9782f8b9fa16df7cd1d349f4c0','cd9767bdf066119e71c3a53efc3967e6']"

   strings:
      $hex_string = { 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
