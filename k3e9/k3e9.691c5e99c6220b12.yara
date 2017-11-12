
rule k3e9_691c5e99c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.691c5e99c6220b12"
     cluster="k3e9.691c5e99c6220b12"
     cluster_size="40"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre supatre waski"
     md5_hashes="['04a97316b601db4254bb760040149d2b','09bc7c615c1bfbb605b8dba14031dd88','ad8fd088533c3f99dfb21af33831c5b8']"

   strings:
      $hex_string = { 0002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
