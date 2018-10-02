
rule n26bb_4b1a17a1ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4b1a17a1ca000b12"
     cluster="n26bb.4b1a17a1ca000b12"
     cluster_size="84"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious dlpnw"
     md5_hashes="['bcb79b7ec9620b7bc4cfe74fec88e5437fa869f6','45c5a95c126c3294a679ec90bb971a8fa3ec24c1','7f28bc2debe75512bc9cd9c5a2a4e08368c38c93']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4b1a17a1ca000b12"

   strings:
      $hex_string = { de203934b82f044279ffcfc4da37d02f57cc64ffe81466bfd9f707506f699272005bfcef4361562ab3f9dd6bf6055f00ef18111005cad76dee36341df1017f3f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
