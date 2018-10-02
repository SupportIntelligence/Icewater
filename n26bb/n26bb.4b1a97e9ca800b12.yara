
rule n26bb_4b1a97e9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4b1a97e9ca800b12"
     cluster="n26bb.4b1a97e9ca800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious heuristic"
     md5_hashes="['9f59f86359c900f55c645c601e903827df9688a1','f4b5a795c348e6c1de5cab638d8e1f6077c0dcd0','c24ad952d41e9e3a358cbb2b99c490d752ae98c6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4b1a97e9ca800b12"

   strings:
      $hex_string = { de203934b82f044279ffcfc4da37d02f57cc64ffe81466bfd9f707506f699272005bfcef4361562ab3f9dd6bf6055f00ef18111005cad76dee36341df1017f3f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
