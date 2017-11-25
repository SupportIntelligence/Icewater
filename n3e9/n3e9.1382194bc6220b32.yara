
rule n3e9_1382194bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1382194bc6220b32"
     cluster="n3e9.1382194bc6220b32"
     cluster_size="99"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bundler fiseria firseria"
     md5_hashes="['072475a1c237c40e32f417a0cb43b8fc','09e009223f547616c8ab770bfb6775bd','260a36ca159f0219a2c1a62e86433255']"

   strings:
      $hex_string = { c8ce8e1bf6179265820584dfd5eb7a54e41aa5ec643359de7fc41cc283b98db719b3d3ea58975ff9684ac70f31573d941026083b88ccad9ea9a41d4b93b47d67 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
