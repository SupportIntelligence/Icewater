import "hash"

rule k3e9_4324f856ddb2e113
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f856ddb2e113"
     cluster="k3e9.4324f856ddb2e113"
     cluster_size="95 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e8fc3ab0d474b40d1e0610c57200c9ef', 'b387f36e75afae3e7454ca4a6fd55a6c', 'a99c3c2a65aeafee13787438dcb8876d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20992,256) == "a5658a555b991c738a328ec7df4c12bc"
}

