
rule m2377_2b912154d6c30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b912154d6c30b12"
     cluster="m2377.2b912154d6c30b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['41e24afa568a1d0ce0d6d1f730608ecc','4eecdb6785eefcfa10bcdb9847ee53f1','be094e5c8d7a033a3b5c03609ed914fd']"

   strings:
      $hex_string = { 3a20274c6f6164696e675c78323668656c6c69703b277d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f5265 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
