
rule m2377_5adb208bc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.5adb208bc6200b12"
     cluster="m2377.5adb208bc6200b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html iframe"
     md5_hashes="['0889ddc6cf3cef0a62810de7aa40e520','0b0d45445f6497bc033671cd6168de9b','f1e1351fc85aae3a6c7efcebe89aa350']"

   strings:
      $hex_string = { 42363139454331453145333437393738413342434446333930353736433236463743334631444235324544413431373638323230303541383635374530423839 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
