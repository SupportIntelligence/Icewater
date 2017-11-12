import "hash"

rule k3e9_52969a99c6200b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52969a99c6200b14"
     cluster="k3e9.52969a99c6200b14"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['02c6d27c552aa6b91a5844917ebe3297','26233d8dae9836c0ff7d1e6020eb2235','eb8982246a8040fad6c4975c67617cdb']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(0,4096) == "00b8c10b0e6b00d1d92f1a0ed679391a"
}

