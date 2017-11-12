
rule k3e9_412e1795a52d6b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.412e1795a52d6b32"
     cluster="k3e9.412e1795a52d6b32"
     cluster_size="33"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['0d7160e755e8f011d8c3677096b03085','2d226529644ed0eea9615e0bc054c5c4','b6d788f1f6370c046360a90b270818bd']"

   strings:
      $hex_string = { 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
