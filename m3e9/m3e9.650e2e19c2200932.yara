
rule m3e9_650e2e19c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.650e2e19c2200932"
     cluster="m3e9.650e2e19c2200932"
     cluster_size="78"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys pronny"
     md5_hashes="['0878b45c3488c60546ba844d5be18fcc','0b0019fcd7f32e2a425b9ba72b8638ef','a339d25911ecdc90926b90d73fa8367b']"

   strings:
      $hex_string = { d7dddbe5eef1161c2b2322251e1e391aafb069e3a6a3a44861599f4222d80000000000000000000000003ce0fbfbc9d5bdfa51d8fbd90f10153333291c340c3d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
