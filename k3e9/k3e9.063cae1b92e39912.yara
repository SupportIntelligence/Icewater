
rule k3e9_063cae1b92e39912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.063cae1b92e39912"
     cluster="k3e9.063cae1b92e39912"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart backdoor berbew"
     md5_hashes="['6b0ebcbb4d8f3e078031176e003e6a02','c6b3f96066d99998f740d7aa12abd548','ef382a9dfd2c31f9ac2be3d98f618538']"

   strings:
      $hex_string = { a3c28bffd2fcf7bd2a7021aa121c084290c79f5948558183ddeec9b82dc5f15d03ce8192738dcf0511b9f0bad5fb07c565060842a93968df6b040a371d6c98e3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
