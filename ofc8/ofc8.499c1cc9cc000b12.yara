
rule ofc8_499c1cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.499c1cc9cc000b12"
     cluster="ofc8.499c1cc9cc000b12"
     cluster_size="1039"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smsreg riskware androidos"
     md5_hashes="['8294fc0541203667a85ea4c121d1ded33e283211','4f187ad88d0f01a48d4e87323620ec5beb712138','d503f7926998a6f2215c8efea9f7a5fc4c39a940']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.499c1cc9cc000b12"

   strings:
      $hex_string = { 2f68021675bd5e6a2e3929f09ce464d7cf1defd0d2522aeef9e2f7ad0ad8061f72dbe63f8da27d974ef290e56eb4f3117073a47867333793384c9e6dc896278b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
