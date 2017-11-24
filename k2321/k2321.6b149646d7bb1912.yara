
rule k2321_6b149646d7bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.6b149646d7bb1912"
     cluster="k2321.6b149646d7bb1912"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bundler installmonster adload"
     md5_hashes="['61102d820832718c7081a18b719ddb47','6a192a2034cfe70e8830d49c17ba9733','dbd00425be747f30be04a9b1cbbf98f2']"

   strings:
      $hex_string = { 2c19a33f05a6ae0c061399ff4042d6e11406789a177d24dcc6c5effc5433eb0fcc374355adf0cb3697014df285882bfcb81c7ea0f32ada8c2ec318dfab7ab0c2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
