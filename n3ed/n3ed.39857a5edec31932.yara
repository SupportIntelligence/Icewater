
rule n3ed_39857a5edec31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39857a5edec31932"
     cluster="n3ed.39857a5edec31932"
     cluster_size="116"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['0cc40cfc04d2cabb03b51b2aeb649dbe','1579e34cbf27acd76bba9a962a0d34ef','468df1e54209aea7f74d7a8ab0c2bdd4']"

   strings:
      $hex_string = { 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
