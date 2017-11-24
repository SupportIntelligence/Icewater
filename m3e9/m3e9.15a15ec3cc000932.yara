
rule m3e9_15a15ec3cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.15a15ec3cc000932"
     cluster="m3e9.15a15ec3cc000932"
     cluster_size="40"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['081240b8351e8640e8486a0c135fcbce','0ffe704a15d37e6d76b4c0c17d5c570d','8d58a48077b28b2eb2e971d23c50a2a8']"

   strings:
      $hex_string = { 45085333db568bf185c974268b551057bffeffff7f2bf92bd08d0c3785c9740d8a0c0284c974068808404e75ec5f85f6750648bb7a000780c600005e8bc35b5d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
