
rule n26bb_0edc7a49c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.0edc7a49c4000b12"
     cluster="n26bb.0edc7a49c4000b12"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab gandcrypt kryptik"
     md5_hashes="['583d707f41887ad686bd2c9def310a14b28fd49e','419dc7e53bcdf7225f3fa844f6b4e5d8a2773bde','6c045659b6c65cf92f05fa57a6bef61a11215c94']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.0edc7a49c4000b12"

   strings:
      $hex_string = { f2c040000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
