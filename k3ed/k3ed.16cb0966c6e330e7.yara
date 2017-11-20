
rule k3ed_16cb0966c6e330e7
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.16cb0966c6e330e7"
     cluster="k3ed.16cb0966c6e330e7"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['011d0c294fa57a237bca011bdc488539','10d7a8e8f873177048203ad98549b352','dd27d03c4b376895d86ad64e07ad341f']"

   strings:
      $hex_string = { f8730c8bc78a08880b40433b0672f68b0680380075bec6030033c05f5b5ec9c20400b809000280ebf256bef0576f50ff36ff74240cff151c106f5085c0741283 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
