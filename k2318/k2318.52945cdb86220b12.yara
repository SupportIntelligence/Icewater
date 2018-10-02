
rule k2318_52945cdb86220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.52945cdb86220b12"
     cluster="k2318.52945cdb86220b12"
     cluster_size="50"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['fae605425405f7cf72ef1c02eb149df5def2ac7c','436990262c89a9d0c8254521535e3aca12a0efa6','8b1f6c3c235b666f07a8804ef73248d431fd45c3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.52945cdb86220b12"

   strings:
      $hex_string = { fce3f3baf2fcf1ff20e6eee2f7ede8ece820eae8f1ebeef2e0ece82e200d0a0d0ad2b3e0ecb3edf320f5ebeef0e8e42028e2b3f2e0ecb3ed20c2312920efe5f0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
