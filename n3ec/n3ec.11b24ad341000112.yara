
rule n3ec_11b24ad341000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11b24ad341000112"
     cluster="n3ec.11b24ad341000112"
     cluster_size="1028"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob vetor"
     md5_hashes="['0089749b618bf30909805b3db15e7e71','00ab2e8669f3b50ca256cc751abd48c4','0bafaf019072a8fb5e55456516013801']"

   strings:
      $hex_string = { 59c643080185f6741f56ff151811d04a598d744602eb9133c08b4dfc5f5e5be800fcfeffc9c2080033c0ebe58d46046683382d8945d80f843d6100000fb75de0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
