
rule o3e9_353b286a9ac36d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.353b286a9ac36d16"
     cluster="o3e9.353b286a9ac36d16"
     cluster_size="713"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['003fa4cdbedefd85cf1b5b38c8a1faf7','0046e45acfd52e88640bebc3e87c76c3','0707352c15512c426c94a14a6773f568']"

   strings:
      $hex_string = { a65e75cc7be67fa2610c0dd4ea202c2e58045aa791f13fb09069419ccda2d8a9567e87d7f8f94a810c50979ad89b011e9ecfad892d9e4d7fe9acfc77836faee5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
