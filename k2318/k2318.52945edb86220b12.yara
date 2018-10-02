
rule k2318_52945edb86220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.52945edb86220b12"
     cluster="k2318.52945edb86220b12"
     cluster_size="3521"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['46f2b98d9caad59b01b0d02b0fc584eca70b6e0c','0d84da9a053957fda605037e70ae84834d3d287d','a2896f8678bb1d401982f5706ff8c3e77f84ee52']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.52945edb86220b12"

   strings:
      $hex_string = { fce3f3baf2fcf1ff20e6eee2f7ede8ece820eae8f1ebeef2e0ece82e200d0a0d0ad2b3e0ecb3edf320f5ebeef0e8e42028e2b3f2e0ecb3ed20c2312920efe5f0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
