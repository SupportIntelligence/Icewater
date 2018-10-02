
rule k2319_6bb49a52dba30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6bb49a52dba30932"
     cluster="k2319.6bb49a52dba30932"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script html scrinject"
     md5_hashes="['b26fdbfe731c6d756faea00692814401378699dc','701d842ead42fba5eb31fcde71ed075a7065995a','98498da4d2a669ed76ac45b095a6b8d3c8418ba1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6bb49a52dba30932"

   strings:
      $hex_string = { 5c2f6a735c2f77702d656d6f6a692d72656c656173652e6d696e2e6a733f7665723d342e392e38227d7d3b0a0909092166756e6374696f6e28612c622c63297b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
