
rule n3ed_119eae89c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.119eae89c0000b16"
     cluster="n3ed.119eae89c0000b16"
     cluster_size="259"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit backdoor nimnul"
     md5_hashes="['01065c2195e206dfb6c35cc64b43b485','046206069987bd4f1c53ce9e45b9ae3f','0ecc3dcdd91dc7740e347aeddcdfb347']"

   strings:
      $hex_string = { 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
