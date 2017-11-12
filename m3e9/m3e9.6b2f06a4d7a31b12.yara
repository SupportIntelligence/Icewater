
rule m3e9_6b2f06a4d7a31b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f06a4d7a31b12"
     cluster="m3e9.6b2f06a4d7a31b12"
     cluster_size="240"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['038088e56b370d67ff95bbaabe0d5feb','05e32305e692f6e775d7e310a59f4ef1','334c5bc8c5ab97f47dcc8b09f7821b4a']"

   strings:
      $hex_string = { 2a73ea3092f4e4d93a0a83f3f66e0e018c61a0eeda4841dfc88a0ddf7ace4ab90211ed5a180882ac4bacb6887e5e323ade3f00164eef2b5ae7410e532faeb3d7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
