
rule j3f4_313c149ec6220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.313c149ec6220932"
     cluster="j3f4.313c149ec6220932"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dotdo engine heuristic"
     md5_hashes="['26a54c02325ff036ace510eb72fd97cf','52bc0d1b4ea989d21c6f6d5425aedb15','bc80b1698144973f6c9dad5c251ab498']"

   strings:
      $hex_string = { 3c737570706f727465644f532049643d227b33353133386239612d356439362d346662642d386532642d6132343430323235663933617d222f3e2d2d3e0d0a0d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
