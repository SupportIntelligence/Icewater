
rule k3e9_0b1a9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b1a9cc9cc000b12"
     cluster="k3e9.0b1a9cc9cc000b12"
     cluster_size="31"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['14091c61e6c71dae6f96ef5718fc444f','15941b78d9b110f0410580c9a0136138','a0e9f4ab8ce7de0b4eac1fd4d9e6210c']"

   strings:
      $hex_string = { ae1aef6194e4a5b79c556a333bf82d9a99df53d90f66e6a90a2c97c72e220e74f05f2fb4e9153f710b2096bebaaa4c12f8ac4f03a6ed16254ec8b3283e27cda2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
