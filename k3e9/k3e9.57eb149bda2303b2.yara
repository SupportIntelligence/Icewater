
rule k3e9_57eb149bda2303b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.57eb149bda2303b2"
     cluster="k3e9.57eb149bda2303b2"
     cluster_size="681"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik trojandownloader"
     md5_hashes="['001e17b03d693ec94c5e7248c941c926','005511ed6ce4a3f0297f50175ac28d6e','10488e3977e660f3c10fa46aff48add3']"

   strings:
      $hex_string = { 006162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a303132333435363738395f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
