
rule k3ec_50b1942a6b314392
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.50b1942a6b314392"
     cluster="k3ec.50b1942a6b314392"
     cluster_size="5"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="resur senna malicious"
     md5_hashes="['a5d51d417ee4d0464b7e6ab437188c3c','a61bbbabed0e16dd111fbb9d83a00527','beb015c817f5c5d90845d220bde83bca']"

   strings:
      $hex_string = { 0583f804750a8d45fc50e80e00000059fec380fb1a72d46a01585bc9c3558bec81ec5c0200008b55085356578bfa83c9ff33c0f2aef7d149807c11ff5c7428bf }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
