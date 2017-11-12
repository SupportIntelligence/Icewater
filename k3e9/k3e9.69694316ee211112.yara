
rule k3e9_69694316ee211112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69694316ee211112"
     cluster="k3e9.69694316ee211112"
     cluster_size="90"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="spyeyes upatre generickd"
     md5_hashes="['0f124666a7abc3e79a52647416ae94dd','1ab7ff1f7b044e81738cd1324f392087','61759a81de7af4476bff4cdc6c347c85']"

   strings:
      $hex_string = { 0002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
