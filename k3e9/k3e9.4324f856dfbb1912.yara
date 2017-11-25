
rule k3e9_4324f856dfbb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f856dfbb1912"
     cluster="k3e9.4324f856dfbb1912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['4e1bd72c1d89130b6e196104e35844ba','ac4c41463a8d9d5f35db1a594e1f36e6','e640bc376e842ab56e5fba3895667548']"

   strings:
      $hex_string = { e08a063ac374043c2076f2895dac8d458050ff157c100001f645ac0174110fb745b0eb0e803e2076d8468975e0ebf56a0a5850565353ffd750e843eaffff8bf0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
