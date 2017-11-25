
rule n3f7_291d7bc9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.291d7bc9c4000b12"
     cluster="n3f7.291d7bc9c4000b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script html"
     md5_hashes="['379d4f484598695d8882a6dcca92039d','48120abf8c0ede299cdf673a09a6aef7','63891f62c18097c78263fd651e15faab']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3327292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
