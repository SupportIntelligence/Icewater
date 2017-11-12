
rule n3e9_31158a9cea208b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31158a9cea208b12"
     cluster="n3e9.31158a9cea208b12"
     cluster_size="63728"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadguide bundler malicious"
     md5_hashes="['00001ceecfb8d35998f8fabedde3ca13','0001450fcaba9442dd60120ef0e5901d','000f4f22775d4c527493db79cad931b0']"

   strings:
      $hex_string = { 005ec1f4a532d5ac96aa1b47deba96e91640ef013fe6e8b27244d2a629321445bfa2279d593b15e12e86a28181b2c9d7a58311ae613ddf0c47bf9a24bf4be8ad }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
