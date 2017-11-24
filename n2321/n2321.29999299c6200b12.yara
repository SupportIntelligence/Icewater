
rule n2321_29999299c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.29999299c6200b12"
     cluster="n2321.29999299c6200b12"
     cluster_size="217"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor injector zusy"
     md5_hashes="['0013c71d99f20815d448c97f83cf154b','01c62b86744d13588ced513ce6880093','0ff079697900d5921a24d20a3dd77715']"

   strings:
      $hex_string = { 5ea31b90ee299ef7bc0817069bf5f260fe42c2342ae6f9410482add013dcdbd8e7c6194f3f7588f41164361458e0575130929d1572745a12aa7f35effa2b7bae }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
