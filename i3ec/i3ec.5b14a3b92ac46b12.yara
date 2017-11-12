import "hash"

rule i3ec_5b14a3b92ac46b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ec.5b14a3b92ac46b12"
     cluster="i3ec.5b14a3b92ac46b12"
     cluster_size="84070"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['0000428941ac7352281e6fc0b595be54','00042f9c59ebdc934e5866d4a87d719a','0020efe0f400137ad72dfa5b159a13f6']"


   condition:
      
      filesize > 1048576 and filesize < 4194304
      and hash.md5(0,262144) == "bbdc9c6d81338f6f1701a1f2e73247ab"
}

