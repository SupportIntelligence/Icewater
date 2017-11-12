
rule o3e9_43b0eb44c0001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0eb44c0001912"
     cluster="o3e9.43b0eb44c0001912"
     cluster_size="373"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit backdoor nimnul"
     md5_hashes="['00957bb706d414880ab775c2500ed6b3','01f391b968e3136f5c015d011ddefec7','14796fb047d7c061e1044feafaa39769']"

   strings:
      $hex_string = { 48000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
