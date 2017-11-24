
rule k3e9_193465e359b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.193465e359b2f316"
     cluster="k3e9.193465e359b2f316"
     cluster_size="88"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted riskware"
     md5_hashes="['06778833d4aa973047d3cb67cb75db63','07bbb98423005df3f2110df2e7009ff9','4c11ce3ee65c2b7d611c95e7eed4045a']"

   strings:
      $hex_string = { 2bc05c604ff1804075a565f3185159c2860d7ddae5ba92fe6aa1579366b661365ee0e2c928547304bbcda0055235afcb6f7bb10fb3acb490d602dd1d3207aee7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
