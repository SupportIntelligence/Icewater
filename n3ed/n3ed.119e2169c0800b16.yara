
rule n3ed_119e2169c0800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.119e2169c0800b16"
     cluster="n3ed.119e2169c0800b16"
     cluster_size="24"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['14290abab29d655c512d485b2b7a1490','15ef795b0e8e10c1a397a3833c7aa08a','c4756e4a1fd0b1205022d516871aeedc']"

   strings:
      $hex_string = { 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
