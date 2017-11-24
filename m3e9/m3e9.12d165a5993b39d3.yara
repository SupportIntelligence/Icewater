
rule m3e9_12d165a5993b39d3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.12d165a5993b39d3"
     cluster="m3e9.12d165a5993b39d3"
     cluster_size="64"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious dangerousobject filerepmalware"
     md5_hashes="['054a306324f92278bb8443638830cb7b','06f15b8453bc465111853aa9ef34c976','3f2e8a064e56d69e70483d7881fd9f89']"

   strings:
      $hex_string = { 58264300e8a99ffeff83c41433c0eb1e8b4508c1f8058b4d0883e11fc1e1068b1485f8dd43000fbe440a0483e0408be55dc3558bec6afe6818a8430068b0f440 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
